package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"nexus-panel/internal/agent/security"
	"nexus-panel/internal/master/model"
)

func doJSONWithAPIKey(r http.Handler, method, path, apiKey string, body any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	req.RemoteAddr = nextIP()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestPhase4EndToEndClosedLoopLifecycle exercises the full cross-module lifecycle spanning:
// TOTP 2FA anti-replay -> Admin X-API-Key -> Invite Registration -> USDT Signed Webhook ->
// Affiliate Commission & Withdrawal & Transfer -> Coupon Preview & Plan Purchase ->
// Forwarding Rule & Subscription -> Ticket Support & Webhook Push -> Paginated Admin Views.
func TestPhase4EndToEndClosedLoopLifecycle(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	prevAllowPrivate := security.DefaultPolicy.AllowPrivateTargets
	security.DefaultPolicy.AllowPrivateTargets = true
	defer func() {
		security.DefaultPolicy.AllowPrivateTargets = prevAllowPrivate
	}()

	var whMu sync.Mutex
	var whEvents []string
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var p struct {
			Event string `json:"event"`
		}
		_ = json.NewDecoder(req.Body).Decode(&p)
		whMu.Lock()
		whEvents = append(whEvents, p.Event)
		whMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer webhookSrv.Close()

	// 1. Admin logs in, enables TOTP 2FA, verifies TOTP login & anti-replay, and issues Admin X-API-Key
	adminTok := login(t, r, "admin@nexus.local", "admin123")

	wSetup := doJSON(r, http.MethodPost, "/api/v1/user/totp/setup", adminTok, nil, "")
	if wSetup.Code != http.StatusOK {
		t.Fatalf("totp setup failed: %d %s", wSetup.Code, wSetup.Body.String())
	}
	var setupData struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(wSetup.Body.Bytes(), &setupData)

	baseNow := time.Now().UTC()
	codePrevStep, err := ComputeTOTPCode(setupData.Secret, baseNow.Add(-30*time.Second))
	if err != nil {
		t.Fatalf("ComputeTOTPCode: %v", err)
	}
	wEnable := doJSON(r, http.MethodPost, "/api/v1/user/totp/enable", adminTok, map[string]any{"code": codePrevStep}, "")
	if wEnable.Code != http.StatusOK {
		t.Fatalf("totp enable failed: %d %s", wEnable.Code, wEnable.Body.String())
	}
	// Pre-2FA JWT must be revoked immediately upon enabling TOTP
	if wStale := doJSON(r, http.MethodGet, "/api/v1/user/profile", adminTok, nil, ""); wStale.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for pre-2FA JWT after TOTP enablement, got %d", wStale.Code)
	}

	// Reusing the exact same 30s step code on login must be rejected by last_totp_step anti-replay!
	if wReplay := doJSON(r, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"email":     "admin@nexus.local",
		"password":  "admin123",
		"totp_code": codePrevStep,
	}, ""); wReplay.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when replaying TOTP step used during enable, got %d", wReplay.Code)
	}

	// Next monotonic 30s step succeeds cleanly and yields fresh post-2FA token
	codeCurrStep, _ := ComputeTOTPCode(setupData.Secret, baseNow)
	wLogin2FA := doJSON(r, http.MethodPost, "/api/v1/auth/login", "", map[string]any{
		"email":     "admin@nexus.local",
		"password":  "admin123",
		"totp_code": codeCurrStep,
	}, "")
	if wLogin2FA.Code != http.StatusOK {
		t.Fatalf("expected 200 on monotonic next TOTP step login, got %d %s", wLogin2FA.Code, wLogin2FA.Body.String())
	}
	var login2FAData struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(wLogin2FA.Body.Bytes(), &login2FAData)
	adminTok = login2FAData.Token

	// Chunked >1MB body to an optional-JSON endpoint must still return 413 Request Entity Too Large
	oversizedJSON := append([]byte(`{"password":"`), bytes.Repeat([]byte("a"), (1<<20)+128)...)
	oversizedJSON = append(oversizedJSON, []byte(`"}`)...)
	reqChunked := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/1/reset-password", bytes.NewReader(oversizedJSON))
	reqChunked.ContentLength = -1
	reqChunked.Header.Set("Authorization", "Bearer "+adminTok)
	reqChunked.Header.Set("Content-Type", "application/json")
	wChunked := httptest.NewRecorder()
	r.ServeHTTP(wChunked, reqChunked)
	if wChunked.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 on chunked >1MB optional-JSON body, got %d: %s", wChunked.Code, wChunked.Body.String())
	}

	wKey := doJSON(r, http.MethodPost, "/api/v1/admin/settings/api-key", adminTok, nil, "")
	if wKey.Code != http.StatusOK {
		t.Fatalf("generate api-key failed: %d %s", wKey.Code, wKey.Body.String())
	}
	var keyData struct {
		APIKey string `json:"api_key"`
	}
	_ = json.Unmarshal(wKey.Body.Bytes(), &keyData)
	adminAPIKey := keyData.APIKey

	// 2. Configure platform settings, plan, and coupon via Admin X-API-Key
	const usdtSecret = "e2e-usdt-webhook-secret-key"
	if w := doJSONWithAPIKey(r, http.MethodPut, "/api/v1/admin/settings", adminAPIKey, map[string]any{
		"allow_register":               true,
		"payment_enabled":              true,
		"usdt_address":                 "TE2ETestTronWalletAddr888",
		"usdt_webhook_secret":          usdtSecret,
		"affiliate_enabled":            true,
		"affiliate_commission_rate":    10.0,
		"affiliate_min_withdraw_cents": 1000,
		"notify_webhook_url":           webhookSrv.URL,
		"notify_on_ticket_events":      true,
	}); w.Code != http.StatusOK {
		t.Fatalf("update settings via API key failed: %d %s", w.Code, w.Body.String())
	}

	wPlan := doJSONWithAPIKey(r, http.MethodPost, "/api/v1/admin/plans", adminAPIKey, map[string]any{
		"name":          "E2E-Pro-Plan",
		"price_cents":   12000, // ¥120.00
		"duration_days": 30,
		"quota_bytes":   200 * 1024 * 1024 * 1024,
		"max_rules":     20,
		"speed_mbps":    300,
		"role_group_id": 1,
	})
	if wPlan.Code != http.StatusCreated {
		t.Fatalf("create E2E plan failed: %d %s", wPlan.Code, wPlan.Body.String())
	}
	var e2ePlan model.Plan
	_ = json.Unmarshal(wPlan.Body.Bytes(), &e2ePlan)

	wCoupon := doJSONWithAPIKey(r, http.MethodPost, "/api/v1/admin/coupons", adminAPIKey, map[string]any{
		"code":               "E2EVIP25",
		"name":               "E2E 75 折神券",
		"type":               "percent",
		"value":              25,
		"min_spend_cents":    5000,
		"max_discount_cents": 5000,
		"allowed_plan_ids":   fmt.Sprintf("%d", e2ePlan.ID),
		"max_uses":           5,
		"per_user_limit":     1,
		"active":             true,
	})
	if wCoupon.Code != http.StatusCreated {
		t.Fatalf("create E2E coupon failed: %d %s", wCoupon.Code, wCoupon.Body.String())
	}

	// 3. Inviter fetches invite_code; Customer registers with invite_code
	inviterTok := login(t, r, "user@nexus.local", "user12345")
	wAff0 := doJSON(r, http.MethodGet, "/api/v1/affiliate/overview", inviterTok, nil, "")
	var aff0 struct {
		InviteCode string `json:"invite_code"`
	}
	_ = json.Unmarshal(wAff0.Body.Bytes(), &aff0)

	wReg := doJSON(r, http.MethodPost, "/api/v1/auth/register", "", map[string]any{
		"email":       "customer@nexus.local",
		"password":    "custPass2026!",
		"invite_code": aff0.InviteCode,
	}, "")
	if wReg.Code != http.StatusCreated {
		t.Fatalf("customer register failed: %d %s", wReg.Code, wReg.Body.String())
	}
	var regData struct {
		Token string     `json:"token"`
		User  model.User `json:"user"`
	}
	_ = json.Unmarshal(wReg.Body.Bytes(), &regData)
	custTok := regData.Token

	// 4. Customer recharges ¥200.00 via USDT -> signed webhook settles balance & 10% (2000c) inviter commission
	wOrd := doJSON(r, http.MethodPost, "/api/v1/orders/recharge", custTok, map[string]any{
		"amount_cents": 20000,
		"gateway":      "usdt",
	}, "")
	if wOrd.Code != http.StatusCreated {
		t.Fatalf("create usdt order failed: %d %s", wOrd.Code, wOrd.Body.String())
	}
	var usdtOrd model.BillingOrder
	_ = json.Unmarshal(wOrd.Body.Bytes(), &usdtOrd)

	ts := time.Now().Unix()
	rawNotify, _ := json.Marshal(map[string]any{
		"order_no":     usdtOrd.OrderNo,
		"tx_hash":      "0xe2e_tron_tx_hash_999",
		"amount_cents": 20000,
		"status":       "paid",
	})
	reqNotify := httptest.NewRequest(http.MethodPost, "/api/v1/pay/usdt/notify", bytes.NewReader(rawNotify))
	reqNotify.Header.Set("Content-Type", "application/json")
	reqNotify.Header.Set("X-USDT-Timestamp", strconv.FormatInt(ts, 10))
	reqNotify.Header.Set("X-USDT-Signature", ComputeUSDTWebhookSign(ts, rawNotify, usdtSecret))
	reqNotify.RemoteAddr = nextIP()
	wNotify := httptest.NewRecorder()
	r.ServeHTTP(wNotify, reqNotify)
	if wNotify.Code != http.StatusOK {
		t.Fatalf("USDT webhook failed: %d %s", wNotify.Code, wNotify.Body.String())
	}

	// Cross-order duplicate tx_hash replay on a second pending order must be rejected (409 Conflict)
	wOrdDup := doJSON(r, http.MethodPost, "/api/v1/orders/recharge", custTok, map[string]any{
		"amount_cents": 20000,
		"gateway":      "usdt",
	}, "")
	var dupOrd model.BillingOrder
	_ = json.Unmarshal(wOrdDup.Body.Bytes(), &dupOrd)
	rawDupNotify, _ := json.Marshal(map[string]any{
		"order_no":     dupOrd.OrderNo,
		"tx_hash":      "0xe2e_tron_tx_hash_999",
		"amount_cents": 20000,
		"status":       "paid",
	})
	reqDup := httptest.NewRequest(http.MethodPost, "/api/v1/pay/usdt/notify", bytes.NewReader(rawDupNotify))
	reqDup.Header.Set("Content-Type", "application/json")
	reqDup.Header.Set("X-USDT-Timestamp", strconv.FormatInt(ts, 10))
	reqDup.Header.Set("X-USDT-Signature", ComputeUSDTWebhookSign(ts, rawDupNotify, usdtSecret))
	reqDup.RemoteAddr = nextIP()
	wDup := httptest.NewRecorder()
	r.ServeHTTP(wDup, reqDup)
	if wDup.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on cross-order duplicate tx_hash, got %d: %s", wDup.Code, wDup.Body.String())
	}

	// 5. Customer previews E2EVIP25 (25% off ¥120 = ¥30 discount, payable ¥90 = 9000c) and buys plan
	wPv := doJSON(r, http.MethodPost, "/api/v1/coupons/preview", custTok, map[string]any{
		"code":    "E2EVIP25",
		"plan_id": e2ePlan.ID,
		"scene":   "plan_purchase",
	}, "")
	if wPv.Code != http.StatusOK {
		t.Fatalf("coupon preview failed: %d %s", wPv.Code, wPv.Body.String())
	}
	wBuy := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/plans/%d/purchase", e2ePlan.ID), custTok, map[string]any{
		"coupon_code": "E2EVIP25",
	}, "")
	if wBuy.Code != http.StatusOK {
		t.Fatalf("plan purchase with coupon failed: %d %s", wBuy.Code, wBuy.Body.String())
	}

	var custAfter model.User
	db.First(&custAfter, regData.User.ID)
	if custAfter.BalanceCents != 11000 {
		t.Fatalf("expected customer balance 11000c (20000 - 9000), got %d", custAfter.BalanceCents)
	}

	// Verify Inviter received strictly 2000c (no double commission!), transfers 1000c to balance, withdraws 1000c -> Admin approves
	var inviter model.User
	db.Where("email = ?", "user@nexus.local").First(&inviter)
	if inviter.CommissionBalanceCents != 2000 || inviter.TotalCommissionCents != 2000 {
		t.Fatalf("expected inviter commission 2000c, got avail=%d total=%d", inviter.CommissionBalanceCents, inviter.TotalCommissionCents)
	}
	if w := doJSON(r, http.MethodPost, "/api/v1/affiliate/transfer", inviterTok, map[string]any{"amount_cents": 1000}, ""); w.Code != http.StatusOK {
		t.Fatalf("inviter partial transfer failed: %d %s", w.Code, w.Body.String())
	}
	wWd := doJSON(r, http.MethodPost, "/api/v1/affiliate/withdraw", inviterTok, map[string]any{
		"amount_cents": 1000,
		"method":       "usdt",
		"account":      "TInviterPayoutAddr777",
	}, "")
	if wWd.Code != http.StatusCreated {
		t.Fatalf("inviter withdraw failed: %d %s", wWd.Code, wWd.Body.String())
	}
	var wdResp struct {
		Withdrawal model.AffiliateWithdrawal `json:"withdrawal"`
	}
	_ = json.Unmarshal(wWd.Body.Bytes(), &wdResp)
	if w := doJSONWithAPIKey(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/affiliate/withdrawals/%d/review", wdResp.Withdrawal.ID), adminAPIKey, map[string]any{
		"action": "approve",
		"remark": "E2E payout complete",
	}); w.Code != http.StatusOK {
		t.Fatalf("admin approve withdrawal via API key failed: %d %s", w.Code, w.Body.String())
	}

	// 6. Customer creates a forwarding rule, pulls JSON subscription, and opens a support ticket linked to the rule
	wRule := doJSON(r, http.MethodPost, "/api/v1/rules", custTok, map[string]any{
		"name":            "E2E-Relay-Rule",
		"mode":            "direct",
		"ingress_node_id": 1,
		"tunnel_line_id":  1,
		"engine":          "native",
		"protocol":        "tcp",
		"listen_port":     0,
		"targets":         []map[string]any{{"address": "1.1.1.1:443"}},
	}, "")
	if wRule.Code != http.StatusCreated {
		t.Fatalf("customer create rule failed: %d %s", wRule.Code, wRule.Body.String())
	}
	var custRule model.ForwardRule
	_ = json.Unmarshal(wRule.Body.Bytes(), &custRule)

	wSub := doJSON(r, http.MethodGet, fmt.Sprintf("/api/v1/sub/%s?format=json", custAfter.SubToken), "", nil, "")
	if wSub.Code != http.StatusOK {
		t.Fatalf("customer subscription pull failed: %d %s", wSub.Code, wSub.Body.String())
	}

	wTk := doJSON(r, http.MethodPost, "/api/v1/tickets", custTok, map[string]any{
		"subject":  "E2E 规则连通性确认",
		"category": "rule",
		"priority": "normal",
		"rule_id":  custRule.ID,
		"message":  "请问该端口是否已实时下发？",
	}, "")
	if wTk.Code != http.StatusCreated {
		t.Fatalf("customer create ticket failed: %d %s", wTk.Code, wTk.Body.String())
	}
	var tkCreated struct {
		Ticket model.SupportTicket `json:"ticket"`
	}
	_ = json.Unmarshal(wTk.Body.Bytes(), &tkCreated)

	if w := doJSONWithAPIKey(r, http.MethodPost, fmt.Sprintf("/api/v1/tickets/%d/reply", tkCreated.Ticket.ID), adminAPIKey, map[string]any{
		"message": "已下发并验证正常，祝使用愉快！",
	}); w.Code != http.StatusOK {
		t.Fatalf("admin reply via API key failed: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/tickets/%d/close", tkCreated.Ticket.ID), custTok, nil, ""); w.Code != http.StatusOK {
		t.Fatalf("customer close ticket failed: %d %s", w.Code, w.Body.String())
	}

	// Verify both ticket_created and ticket_replied webhook notifications arrived
	deadline := time.Now().Add(2 * time.Second)
	gotCreate, gotReply := false, false
	for time.Now().Before(deadline) {
		whMu.Lock()
		for _, ev := range whEvents {
			if ev == "ticket_created" {
				gotCreate = true
			}
			if ev == "ticket_replied" {
				gotReply = true
			}
		}
		whMu.Unlock()
		if gotCreate && gotReply {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !gotCreate || !gotReply {
		t.Fatalf("expected ticket_created & ticket_replied webhooks in E2E flow, got %v", whEvents)
	}

	// 7. Verify 2 consecutive manual order confirmations by the same admin succeed without trade_no collision
	for i := 0; i < 2; i++ {
		wM := doJSON(r, http.MethodPost, "/api/v1/orders/recharge", custTok, map[string]any{
			"amount_cents": 1000,
			"gateway":      "usdt",
		}, "")
		if wM.Code != http.StatusCreated {
			t.Fatalf("create manual-confirm order #%d failed: %d %s", i+1, wM.Code, wM.Body.String())
		}
		var mOrd model.BillingOrder
		_ = json.Unmarshal(wM.Body.Bytes(), &mOrd)
		wConf := doJSONWithAPIKey(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/orders/%d/confirm", mOrd.ID), adminAPIKey, nil)
		if wConf.Code != http.StatusOK {
			t.Fatalf("admin manual confirm #%d failed (trade_no collision check): %d %s", i+1, wConf.Code, wConf.Body.String())
		}
	}

	// 8. Verify paginated envelopes and portable LIKE ... ESCAPE '!' wildcard neutralization across list endpoints
	for _, ep := range []string{
		"/api/v1/admin/coupons?page=1&page_size=10&paged=1",
		"/api/v1/admin/affiliate/withdrawals?page=1&page_size=10&paged=1",
		"/api/v1/admin/tickets?page=1&page_size=10&paged=1",
		"/api/v1/orders?all=1&page=1&page_size=10&paged=1",
		"/api/v1/admin/audit-logs?page=1&page_size=10&paged=1",
	} {
		w := doJSONWithAPIKey(r, http.MethodGet, ep, adminAPIKey, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("paginated check %s failed: %d %s", ep, w.Code, w.Body.String())
		}
		var env struct {
			Total int64 `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil || env.Total < 1 {
			t.Fatalf("expected total >= 1 on %s, got err=%v body=%s", ep, err, w.Body.String())
		}

		// Wildcards '%', '_', escape char '!', and '\' must be treated literally (0 false-positive matches)
		wEsc := doJSONWithAPIKey(r, http.MethodGet, ep+"&q=%25_!nonexistent%5C", adminAPIKey, nil)
		if wEsc.Code != http.StatusOK {
			t.Fatalf("escaped LIKE check %s failed: %d %s", ep, wEsc.Code, wEsc.Body.String())
		}
		var escEnv struct {
			Total int64 `json:"total"`
		}
		if err := json.Unmarshal(wEsc.Body.Bytes(), &escEnv); err != nil || escEnv.Total != 0 {
			t.Fatalf("expected 0 matches for literal wildcard query on %s, got total=%d err=%v", ep, escEnv.Total, err)
		}
	}
}
