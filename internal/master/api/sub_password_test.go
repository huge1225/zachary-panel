package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"nexus-panel/internal/master/model"
)

func TestAdminResetUserPasswordAndSessionRevocation(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	var u model.User
	if err := db.Where("email = ?", "user@nexus.local").First(&u).Error; err != nil {
		t.Fatal(err)
	}

	// Non-admin cannot reset anyone's password
	if w := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/reset-password", u.ID), userTok, map[string]any{}, ""); w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d", w.Code)
	}

	// 1. Admin resets user password to a custom password
	w := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/reset-password", u.ID), adminTok, map[string]any{
		"password": "CustomNewPass#2026",
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("reset password custom failed: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Password  string `json:"password"`
		Generated bool   `json:"generated"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Password != "CustomNewPass#2026" || resp.Generated {
		t.Fatalf("unexpected custom reset resp: %+v", resp)
	}

	// Old user JWT must be immediately rejected (token_version incremented)
	if w := doJSON(r, http.MethodGet, "/api/v1/user/profile", userTok, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected old user JWT to be revoked (401), got %d", w.Code)
	}

	// User can log in with the new custom password
	userTok2 := login(t, r, "user@nexus.local", "CustomNewPass#2026")
	if w := doJSON(r, http.MethodGet, "/api/v1/user/profile", userTok2, nil, ""); w.Code != http.StatusOK {
		t.Fatalf("expected new user JWT to work, got %d", w.Code)
	}

	// 2. Admin resets user password with empty body -> random password generated
	w2 := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/reset-password", u.ID), adminTok, map[string]any{}, "")
	if w2.Code != http.StatusOK {
		t.Fatalf("reset password random failed: %d %s", w2.Code, w2.Body.String())
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &resp)
	if len(resp.Password) != 16 || !resp.Generated {
		t.Fatalf("expected 16-char generated password, got %+v", resp)
	}
	if w := doJSON(r, http.MethodGet, "/api/v1/user/profile", userTok2, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected second user JWT to be revoked (401), got %d", w.Code)
	}
	_ = login(t, r, "user@nexus.local", resp.Password)
}

func TestSubscriptionLinkAndTokenRotation(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	var u model.User
	if err := db.Where("email = ?", "user@nexus.local").First(&u).Error; err != nil {
		t.Fatal(err)
	}
	if len(u.SubToken) < 16 {
		t.Fatalf("expected user to have initial SubToken, got %q", u.SubToken)
	}

	// Create a forwarding rule for the user
	wRule := doJSON(r, http.MethodPost, "/api/v1/rules", userTok, map[string]any{
		"name":           "sub-rule-1",
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"listen_port":    0,
		"targets":        []map[string]string{{"address": "1.1.1.1:443"}},
	}, "")
	if wRule.Code != http.StatusCreated {
		t.Fatalf("create rule failed: %d %s", wRule.Code, wRule.Body.String())
	}

	// Fetch default Base64 subscription
	wSub := doJSON(r, http.MethodGet, "/api/v1/sub/"+u.SubToken, "", nil, "")
	if wSub.Code != http.StatusOK {
		t.Fatalf("get subscription failed: %d %s", wSub.Code, wSub.Body.String())
	}
	if !strings.Contains(wSub.Header().Get("Subscription-Userinfo"), "total=") {
		t.Fatalf("missing Subscription-Userinfo header: %q", wSub.Header().Get("Subscription-Userinfo"))
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(wSub.Body.String()))
	if err != nil || !strings.Contains(string(decoded), "sub-rule-1") {
		t.Fatalf("unexpected decoded sub body: %q (err=%v)", string(decoded), err)
	}

	// Fetch JSON subscription
	wJSON := doJSON(r, http.MethodGet, "/api/v1/sub/"+u.SubToken+"?format=json", "", nil, "")
	if wJSON.Code != http.StatusOK {
		t.Fatalf("get json subscription failed: %d %s", wJSON.Code, wJSON.Body.String())
	}
	var subData struct {
		Email      string `json:"email"`
		CanForward bool   `json:"can_forward"`
		Rules      []struct {
			Name  string `json:"name"`
			Entry string `json:"entry"`
		} `json:"rules"`
	}
	_ = json.Unmarshal(wJSON.Body.Bytes(), &subData)
	if !subData.CanForward || len(subData.Rules) != 1 || subData.Rules[0].Name != "sub-rule-1" {
		t.Fatalf("unexpected json subscription payload: %+v", subData)
	}

	// User rotates their own sub_token
	oldToken := u.SubToken
	wRot := doJSON(r, http.MethodPost, "/api/v1/user/reset-sub-token", userTok, nil, "")
	if wRot.Code != http.StatusOK {
		t.Fatalf("user reset sub token failed: %d %s", wRot.Code, wRot.Body.String())
	}
	var rotResp struct {
		SubToken string `json:"sub_token"`
	}
	_ = json.Unmarshal(wRot.Body.Bytes(), &rotResp)
	if rotResp.SubToken == "" || rotResp.SubToken == oldToken {
		t.Fatalf("expected new sub_token, got %q", rotResp.SubToken)
	}

	// Old token must return 404
	if w := doJSON(r, http.MethodGet, "/api/v1/sub/"+oldToken, "", nil, ""); w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for old sub_token, got %d", w.Code)
	}
	// New token works
	if w := doJSON(r, http.MethodGet, "/api/v1/sub/"+rotResp.SubToken, "", nil, ""); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for new sub_token, got %d", w.Code)
	}

	// Admin rotates user's sub_token
	oldToken2 := rotResp.SubToken
	wAdminRot := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/reset-sub-token", u.ID), adminTok, nil, "")
	if wAdminRot.Code != http.StatusOK {
		t.Fatalf("admin reset sub token failed: %d %s", wAdminRot.Code, wAdminRot.Body.String())
	}
	_ = json.Unmarshal(wAdminRot.Body.Bytes(), &rotResp)
	if rotResp.SubToken == "" || rotResp.SubToken == oldToken2 {
		t.Fatalf("expected new sub_token from admin reset, got %q", rotResp.SubToken)
	}
	if w := doJSON(r, http.MethodGet, "/api/v1/sub/"+oldToken2, "", nil, ""); w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for previous sub_token after admin reset, got %d", w.Code)
	}
	if w := doJSON(r, http.MethodGet, "/api/v1/sub/"+rotResp.SubToken, "", nil, ""); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin-rotated sub_token, got %d", w.Code)
	}
}

func TestAdminResetUserSubscriptionAndEditExpiry(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	var u model.User
	db.Where("email = ?", "user@nexus.local").First(&u)

	// Create a rule for the user
	wRule := doJSON(r, http.MethodPost, "/api/v1/rules", userTok, map[string]any{
		"name":           "quota-rule",
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"listen_port":    0,
		"targets":        []map[string]string{{"address": "1.1.1.1:443"}},
	}, "")
	if wRule.Code != http.StatusCreated {
		t.Fatalf("create rule: %d %s", wRule.Code, wRule.Body.String())
	}
	var rule model.ForwardRule
	_ = json.Unmarshal(wRule.Body.Bytes(), &rule)

	// Simulate user exhausting quota and expiring
	db.Model(&model.User{}).Where("id = ?", u.ID).Updates(map[string]any{
		"used_bytes": u.QuotaBytes + 1024,
		"expire_at":  time.Now().Add(-48 * time.Hour),
	})
	db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Updates(map[string]any{
		"enabled": false,
		"status":  "quota_exceeded",
	})

	// Admin calls reset-subscription
	wReset := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/reset-subscription", u.ID), adminTok, map[string]any{}, "")
	if wReset.Code != http.StatusOK {
		t.Fatalf("admin reset subscription failed: %d %s", wReset.Code, wReset.Body.String())
	}
	db.First(&u, u.ID)
	if u.UsedBytes != 0 || !u.ExpireAt.After(time.Now().Add(20*24*time.Hour)) {
		t.Fatalf("expected used_bytes=0 and extended expire_at, got used=%d expire=%v", u.UsedBytes, u.ExpireAt)
	}
	db.First(&rule, rule.ID)
	if !rule.Enabled || (rule.Status != "running" && rule.Status != "syncing") {
		t.Fatalf("expected quota_exceeded rule to auto-resume, got enabled=%v status=%s", rule.Enabled, rule.Status)
	}

	// Admin edits expire_at to a past date via PUT /api/v1/admin/users/:id -> rule should be cut off
	wPast := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", u.ID), adminTok, map[string]any{
		"expire_at": "2020-01-01",
	}, "")
	if wPast.Code != http.StatusOK {
		t.Fatalf("admin update expire_at past failed: %d %s", wPast.Code, wPast.Body.String())
	}
	db.First(&rule, rule.ID)
	if rule.Enabled || rule.Status != "quota_exceeded" {
		t.Fatalf("expected expired user's rule to be cut off, got enabled=%v status=%s", rule.Enabled, rule.Status)
	}

	// Admin edits expire_at to a future date -> rule should auto-resume
	wFuture := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", u.ID), adminTok, map[string]any{
		"expire_at": "2030-12-31",
	}, "")
	if wFuture.Code != http.StatusOK {
		t.Fatalf("admin update expire_at future failed: %d %s", wFuture.Code, wFuture.Body.String())
	}
	db.First(&rule, rule.ID)
	if !rule.Enabled || (rule.Status != "running" && rule.Status != "syncing") {
		t.Fatalf("expected rule to auto-resume after extending expire_at, got enabled=%v status=%s", rule.Enabled, rule.Status)
	}
}

func TestUserPaidResetSubscription(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	userTok := login(t, r, "user@nexus.local", "user12345")

	var u model.User
	db.Where("email = ?", "user@nexus.local").First(&u)

	// Create a rule and mark it quota_exceeded
	wRule := doJSON(r, http.MethodPost, "/api/v1/rules", userTok, map[string]any{
		"name":           "paid-reset-rule",
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"listen_port":    0,
		"targets":        []map[string]string{{"address": "1.1.1.1:443"}},
	}, "")
	if wRule.Code != http.StatusCreated {
		t.Fatalf("create rule: %d %s", wRule.Code, wRule.Body.String())
	}
	var rule model.ForwardRule
	_ = json.Unmarshal(wRule.Body.Bytes(), &rule)

	// 1. Insufficient balance -> 402 Payment Required
	db.Model(&model.User{}).Where("id = ?", u.ID).Updates(map[string]any{
		"balance_cents": 100, // plan #1 costs 1900 cents
		"used_bytes":    u.QuotaBytes,
	})
	db.Model(&model.ForwardRule{}).Where("id = ?", rule.ID).Updates(map[string]any{
		"enabled": false,
		"status":  "quota_exceeded",
	})
	if w := doJSON(r, http.MethodPost, "/api/v1/user/reset-subscription", userTok, nil, ""); w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 when balance insufficient, got %d %s", w.Code, w.Body.String())
	}

	// 2. Free plan (price_cents = 0) -> 400 Bad Request (cannot abuse free plan to reset quota infinitely)
	freePlan := model.Plan{
		Name:         "Free Trial",
		RoleGroupID:  1,
		PriceCents:   0,
		DurationDays: 30,
		QuotaBytes:   10 * 1024 * 1024 * 1024,
		MaxRules:     5,
		SpeedMbps:    50,
		Active:       true,
	}
	db.Create(&freePlan)
	db.Model(&model.User{}).Where("id = ?", u.ID).Update("plan_id", freePlan.ID)
	if w := doJSON(r, http.MethodPost, "/api/v1/user/reset-subscription", userTok, nil, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for free plan reset, got %d %s", w.Code, w.Body.String())
	}

	// 3. Sufficient balance on paid plan #1 -> deducts price, resets used_bytes=0, extends expire_at, resumes rule
	db.Model(&model.User{}).Where("id = ?", u.ID).Updates(map[string]any{
		"plan_id":       1,
		"balance_cents": 5000,
	})
	wOK := doJSON(r, http.MethodPost, "/api/v1/user/reset-subscription", userTok, nil, "")
	if wOK.Code != http.StatusOK {
		t.Fatalf("paid reset subscription failed: %d %s", wOK.Code, wOK.Body.String())
	}
	db.First(&u, u.ID)
	if u.BalanceCents != 3100 || u.UsedBytes != 0 {
		t.Fatalf("expected balance=3100 and used_bytes=0, got balance=%d used=%d", u.BalanceCents, u.UsedBytes)
	}
	db.First(&rule, rule.ID)
	if !rule.Enabled || (rule.Status != "running" && rule.Status != "syncing") {
		t.Fatalf("expected quota_exceeded rule to auto-resume after paid reset, got enabled=%v status=%s", rule.Enabled, rule.Status)
	}
}
