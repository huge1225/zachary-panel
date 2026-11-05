package api

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"nexus-panel/internal/master/model"
)

// NEW-D: resetting the traffic of a banned (or expired) user must not bring its rules back online.
func TestResetTrafficDoesNotResumeBannedUser(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	uid := userIDByEmail(t, db, "user@nexus.local")
	var node model.Node
	if err := db.First(&node).Error; err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		updates map[string]any
	}{
		{"banned", map[string]any{"status": "banned"}},
		{"expired", map[string]any{"status": "active", "expire_at": time.Now().Add(-time.Hour)}},
	} {
		db.Model(&model.User{}).Where("id = ?", uid).Updates(tc.updates)
		rule := model.ForwardRule{UserID: uid, Name: "r-" + tc.name, Mode: "tunnel", TunnelLineID: 1, IngressNodeID: node.ID,
			Engine: "native", Protocol: "tcp", TargetsJSON: `[{"address":"1.1.1.1:443"}]`, ListenPort: 40000 + len(tc.name),
			Enabled: false, Status: "quota_exceeded"}
		if err := db.Create(&rule).Error; err != nil {
			t.Fatal(err)
		}
		db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Update("enabled", false)
		if w := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/reset-traffic", uid), admin, nil, ""); w.Code != http.StatusOK {
			t.Fatalf("%s: reset traffic: %d %s", tc.name, w.Code, w.Body.String())
		}
		var got model.ForwardRule
		db.First(&got, rule.ID)
		if got.Enabled || got.Status != "quota_exceeded" {
			t.Fatalf("%s user's rule was resumed: enabled=%v status=%s", tc.name, got.Enabled, got.Status)
		}
	}
}

func TestCanForward(t *testing.T) {
	now := time.Now()
	cases := []struct {
		u    model.User
		want bool
	}{
		{model.User{Status: "active", QuotaBytes: 10, UsedBytes: 1}, true},
		{model.User{Status: "banned", QuotaBytes: 10, UsedBytes: 1}, false},
		{model.User{Status: "active", QuotaBytes: 10, UsedBytes: 10}, false},
		{model.User{Status: "active", QuotaBytes: 10, ExpireAt: now.Add(-time.Minute)}, false},
		{model.User{Status: "active", QuotaBytes: 10, ExpireAt: now.Add(time.Hour)}, true},
	}
	for i, c := range cases {
		if got := c.u.CanForward(now); got != c.want {
			t.Fatalf("case %d: CanForward=%v want %v", i, got, c.want)
		}
	}
}

// R3-N3: targets pointing back at a panel node (e.g. a 1:1 NATed public IP) are rejected.
func TestRuleTargetCannotBeNodeAddress(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	var node model.Node
	if err := db.First(&node).Error; err != nil {
		t.Fatal(err)
	}
	db.Model(&model.Node{}).Where("id = ?", node.ID).Update("connect_ip", "9.9.9.9")
	w := doJSON(r, http.MethodPost, "/api/v1/rules", admin, map[string]any{
		"name": "hairpin", "mode": "direct", "ingress_node_id": node.ID, "protocol": "tcp",
		"targets": []map[string]string{{"address": "9.9.9.9:22"}},
	}, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("target equal to a node address must be rejected, got %d %s", w.Code, w.Body.String())
	}
}
