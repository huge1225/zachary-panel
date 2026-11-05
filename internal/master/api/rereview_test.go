package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"gorm.io/gorm"
	"nexus-panel/internal/master/model"
)

func userIDByEmail(t *testing.T, db *gorm.DB, email string) uint64 {
	t.Helper()
	var u model.User
	if err := db.Where("email = ?", email).First(&u).Error; err != nil {
		t.Fatalf("user %s not found: %v", email, err)
	}
	return u.ID
}

// N4: failures from attacker IPs must not lock the legitimate user out.
func TestLockoutDoesNotAllowAdminDoS(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()
	defer accountGuard.reset("admin@nexus.local")
	for i := 0; i < 15; i++ { // distinct attacker IPs (below the distributed threshold)
		doJSON(r, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"email": "admin@nexus.local", "password": "wrong-pass"}, "")
	}
	login(t, r, "admin@nexus.local", "admin123")
}

func TestAccountLockoutUnit(t *testing.T) {
	g := newAccountLockout()
	email := "victim@example.com"
	for i := 0; i < accountLockThreshold; i++ {
		g.fail(email, "1.1.1.1")
	}
	if !g.locked(email, "1.1.1.1") {
		t.Fatal("attacker IP must be locked after threshold")
	}
	if g.locked(email, "2.2.2.2") {
		t.Fatal("other IPs must not be locked by a single attacker IP")
	}
	g.success(email, "3.3.3.3") // known-good IP of the owner
	for i := 0; i < accountGlobalLockThreshold; i++ {
		g.fail(email, fmt.Sprintf("10.0.%d.%d", i/250, i%250))
	}
	if !g.locked(email, "4.4.4.4") {
		t.Fatal("unknown IPs must be locked after distributed guessing")
	}
	if g.locked(email, "3.3.3.3") {
		t.Fatal("owner's known IP must stay exempt from the distributed lock")
	}
}

// N5: full-row saves must not overwrite concurrently incremented traffic counters.
func TestToggleDoesNotOverwriteTrafficCounters(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	var node model.Node
	if err := db.First(&node).Error; err != nil {
		t.Fatal(err)
	}
	w := doJSON(r, http.MethodPost, "/api/v1/rules", admin, map[string]any{
		"name": "c1", "mode": "direct", "ingress_node_id": node.ID, "protocol": "tcp",
		"targets": []map[string]string{{"address": "1.1.1.1:443"}},
	}, "")
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create rule: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		ID uint64 `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.ID == 0 {
		var rr struct {
			Rule struct {
				ID uint64 `json:"id"`
			} `json:"rule"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &rr)
		created.ID = rr.Rule.ID
	}
	// Simulate a traffic report landing after the handler loaded the rule.
	db.Model(&model.ForwardRule{}).Where("id = ?", created.ID).Updates(map[string]any{
		"upload_bytes": gorm.Expr("upload_bytes + ?", 1000), "billed_bytes": gorm.Expr("billed_bytes + ?", 2000),
	})
	if w := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/rules/%d/toggle", created.ID), admin, nil, ""); w.Code != http.StatusOK {
		t.Fatalf("toggle: %d", w.Code)
	}
	var rule model.ForwardRule
	db.First(&rule, created.ID)
	if rule.UploadBytes != 1000 || rule.BilledBytes != 2000 {
		t.Fatalf("traffic counters overwritten by toggle: up=%d billed=%d", rule.UploadBytes, rule.BilledBytes)
	}
}

// N5: admin profile edits must not reset balance / usage changed concurrently.
func TestAdminUpdateUserKeepsConcurrentCounters(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	uid := userIDByEmail(t, db, "user@nexus.local")
	db.Model(&model.User{}).Where("id = ?", uid).Updates(map[string]any{"used_bytes": 12345, "balance_cents": 777})
	w := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", uid), admin, map[string]any{"max_rules": 9}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("update user: %d %s", w.Code, w.Body.String())
	}
	var u model.User
	db.First(&u, uid)
	if u.UsedBytes != 12345 || u.BalanceCents != 777 || u.MaxRules != 9 {
		t.Fatalf("unexpected user state: used=%d balance=%d max=%d", u.UsedBytes, u.BalanceCents, u.MaxRules)
	}
}

// N6: re-buying a free plan must not reset used traffic.
func TestFreePlanDoesNotResetUsage(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	plan := model.Plan{Name: "free", PriceCents: 0, QuotaBytes: 1 << 30, DurationDays: 30, Active: true}
	if err := db.Create(&plan).Error; err != nil {
		t.Fatal(err)
	}
	uid := userIDByEmail(t, db, "user@nexus.local")
	db.Model(&model.User{}).Where("id = ?", uid).Update("used_bytes", 5000)
	tok := login(t, r, "user@nexus.local", "user12345")
	if w := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/plans/%d/purchase", plan.ID), tok, nil, ""); w.Code != http.StatusOK {
		t.Fatalf("purchase free plan: %d %s", w.Code, w.Body.String())
	}
	var u model.User
	db.First(&u, uid)
	if u.UsedBytes != 5000 {
		t.Fatalf("free plan reset used_bytes to %d", u.UsedBytes)
	}
}

// N7: expired users cannot create rules.
func TestExpiredUserCannotCreateRule(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	uid := userIDByEmail(t, db, "user@nexus.local")
	db.Model(&model.User{}).Where("id = ?", uid).Update("expire_at", time.Now().Add(-time.Hour))
	tok := login(t, r, "user@nexus.local", "user12345")
	w := doJSON(r, http.MethodPost, "/api/v1/rules", tok, map[string]any{
		"name": "x", "mode": "tunnel", "tunnel_line_id": 1, "protocol": "tcp",
		"targets": []map[string]string{{"address": "1.1.1.1:443"}},
	}, "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("expired user should get 403, got %d %s", w.Code, w.Body.String())
	}
}

// N2: rule mutations are throttled per user.
func TestRuleMutationRateLimited(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()
	tok := login(t, r, "user@nexus.local", "user12345")
	limited := false
	for i := 0; i < 40; i++ {
		w := doJSON(r, http.MethodPost, "/api/v1/rules/999999/toggle", tok, nil, "")
		if w.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("rule toggles must be rate limited per user")
	}
}

// N12: CSP present.
func TestCSPHeader(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()
	w := doJSON(r, http.MethodGet, "/api/v1/site-config", "", nil, "")
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP header")
	}
}
