package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
)

var ipCounter uint32

// nextIP returns a unique client address so the per-IP login limiter does not interfere between test cases.
func nextIP() string {
	n := atomic.AddUint32(&ipCounter, 1)
	return fmt.Sprintf("198.51.%d.%d:4000", (n>>8)&0xff, n&0xff)
}

func doJSON(r *gin.Engine, method, path, token string, body any, remote string) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if remote == "" {
		remote = nextIP()
	}
	req.RemoteAddr = remote
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func login(t *testing.T, r *gin.Engine, email, pw string) string {
	t.Helper()
	w := doJSON(r, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"email": email, "password": pw}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("login %s failed: %d %s", email, w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return resp.Token
}

func TestRegisterDisabledByDefault(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()
	w := doJSON(r, http.MethodPost, "/api/v1/auth/register", "", map[string]string{"email": "new@example.com", "password": "Passw0rd!x"}, "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("register must be disabled by default, got %d", w.Code)
	}
}

func TestNoSeededRedeemCodeAndNoSecretsInResponses(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()
	tok := login(t, r, "user@nexus.local", "user12345")
	w := doJSON(r, http.MethodPost, "/api/v1/redeem", tok, map[string]string{"code": "NEXUS-VIP-2026"}, "")
	if w.Code == http.StatusOK {
		t.Fatal("legacy hard-coded redeem code must not exist")
	}
	w = doJSON(r, http.MethodGet, "/api/v1/user/profile", tok, nil, "")
	if strings.Contains(strings.ToLower(w.Body.String()), "password") || strings.Contains(w.Body.String(), "$2a$") {
		t.Fatalf("profile leaks password hash: %s", w.Body.String())
	}
	admin := login(t, r, "admin@nexus.local", "admin123")
	w = doJSON(r, http.MethodGet, "/api/v1/nodes", admin, nil, "")
	if strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatal("node list must not expose tunnel cert PEM")
	}
	w = doJSON(r, http.MethodGet, "/api/v1/nodes", tok, nil, "")
	if strings.Contains(w.Body.String(), "\"token\"") {
		t.Fatalf("user node list leaks node token: %s", w.Body.String())
	}
}

func TestRuleInputValidation(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	targets := make([]map[string]string, 33)
	for i := range targets {
		targets[i] = map[string]string{"address": "1.1.1.1:443"}
	}
	cases := []map[string]any{
		{"name": "bad-proto", "protocol": "icmp", "listen_port": 30001, "targets": []map[string]string{{"address": "1.1.1.1:443"}}},
		{"name": "too-many", "protocol": "tcp", "listen_port": 30002, "targets": targets},
		{"name": "no-targets", "protocol": "tcp", "listen_port": 30003, "targets": []map[string]string{}},
		{"name": "bad-lb", "protocol": "tcp", "load_balance": "evil", "listen_port": 30004, "targets": []map[string]string{{"address": "1.1.1.1:443"}}},
		{"name": strings.Repeat("x", 100), "protocol": "tcp", "listen_port": 30005, "targets": []map[string]string{{"address": "1.1.1.1:443"}}},
		{"name": "ssrf", "protocol": "tcp", "listen_port": 30006, "targets": []map[string]string{{"address": "169.254.169.254:80"}}},
		{"name": "ssrf-local", "protocol": "tcp", "listen_port": 30007, "targets": []map[string]string{{"address": "127.0.0.1:22"}}},
	}
	for _, body := range cases {
		w := doJSON(r, http.MethodPost, "/api/v1/rules", admin, body, "")
		if w.Code != http.StatusBadRequest {
			t.Errorf("rule %v should be rejected with 400, got %d %s", body["name"], w.Code, w.Body.String())
		}
	}
}

func TestPasswordChangeRevokesOldToken(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()
	old := login(t, r, "user@nexus.local", "user12345")
	w := doJSON(r, http.MethodPost, "/api/v1/user/password", old, map[string]string{"old_password": "wrong-password", "new_password": "NewPassw0rd"}, "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong old password must be rejected, got %d", w.Code)
	}
	w = doJSON(r, http.MethodPost, "/api/v1/user/password", old, map[string]string{"old_password": "user12345", "new_password": "short"}, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("short password must be rejected, got %d", w.Code)
	}
	w = doJSON(r, http.MethodPost, "/api/v1/user/password", old, map[string]string{"old_password": "user12345", "new_password": "NewPassw0rd"}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("change password failed: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if w := doJSON(r, http.MethodGet, "/api/v1/user/profile", old, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("old token must be revoked, got %d", w.Code)
	}
	if w := doJSON(r, http.MethodGet, "/api/v1/user/profile", resp.Token, nil, ""); w.Code != http.StatusOK {
		t.Fatalf("new token should work, got %d", w.Code)
	}
	login(t, r, "user@nexus.local", "NewPassw0rd")
}

func TestBanRevokesTokenAndNoSelfDemote(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	user := login(t, r, "user@nexus.local", "user12345")

	var prof struct {
		ID   uint64 `json:"id"`
		User struct {
			ID uint64 `json:"id"`
		} `json:"user"`
	}
	w := doJSON(r, http.MethodGet, "/api/v1/user/profile", user, nil, "")
	_ = json.Unmarshal(w.Body.Bytes(), &prof)
	uid := prof.ID
	if uid == 0 {
		uid = prof.User.ID
	}
	if uid == 0 {
		t.Fatalf("cannot parse profile: %s", w.Body.String())
	}
	w = doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", uid), admin, map[string]any{"status": "banned"}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("ban failed: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(r, http.MethodGet, "/api/v1/user/profile", user, nil, ""); w.Code == http.StatusOK {
		t.Fatal("banned user's token must stop working")
	}

	w = doJSON(r, http.MethodGet, "/api/v1/user/profile", admin, nil, "")
	prof.ID, prof.User.ID = 0, 0
	_ = json.Unmarshal(w.Body.Bytes(), &prof)
	aid := prof.ID
	if aid == 0 {
		aid = prof.User.ID
	}
	w = doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", aid), admin, map[string]any{"role": "user"}, "")
	if w.Code == http.StatusOK {
		t.Fatal("admin must not be able to demote themselves")
	}
	w = doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", uid), admin, map[string]any{"role": "superroot"}, "")
	if w.Code == http.StatusOK {
		t.Fatal("invalid role must be rejected")
	}
}

func TestLoginLockoutAndXFFIgnored(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()

	// Spoofed X-Forwarded-For must not bypass the per-IP limiter (no trusted proxies configured).
	remote := nextIP()
	limited := false
	for i := 0; i < 12; i++ {
		b, _ := json.Marshal(map[string]string{"email": "nobody@example.com", "password": "x"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i+1))
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("per-IP login limiter bypassed via X-Forwarded-For")
	}

	// Per-account lockout semantics are covered by TestAccountLockoutUnit / TestLockoutDoesNotAllowAdminDoS.
}

func TestForgedAndAlgNoneTokensRejected(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()
	// alg=none token claiming admin
	forged := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJleHAiOjQxMDI0NDQ4MDB9."
	for _, tok := range []string{forged, "garbage", ""} {
		if w := doJSON(r, http.MethodGet, "/api/v1/admin/settings", tok, nil, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("token %q should yield 401, got %d", tok, w.Code)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()
	w := doJSON(r, http.MethodGet, "/api/v1/site-config", "", nil, "")
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options")
	}
	if w.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Error("CORS must not be wildcard")
	}
}
