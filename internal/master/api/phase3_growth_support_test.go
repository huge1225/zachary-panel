package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nexus-panel/internal/agent/security"
	"nexus-panel/internal/master/model"
)

func TestPhase3CouponsPreviewRedemptionAndConcurrency(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	// Create two test plans: Standard (¥50 = 5000c) and Flagship (¥200 = 20000c)
	wP1 := doJSON(r, http.MethodPost, "/api/v1/admin/plans", adminTok, map[string]any{
		"name":          "P3-Standard",
		"price_cents":   5000,
		"duration_days": 30,
		"quota_bytes":   100 * 1024 * 1024 * 1024,
		"max_rules":     10,
		"speed_mbps":    100,
		"role_group_id": 1,
	}, "")
	if wP1.Code != http.StatusCreated {
		t.Fatalf("create P1 failed: %d %s", wP1.Code, wP1.Body.String())
	}
	var planStd model.Plan
	_ = json.Unmarshal(wP1.Body.Bytes(), &planStd)

	wP2 := doJSON(r, http.MethodPost, "/api/v1/admin/plans", adminTok, map[string]any{
		"name":          "P3-Flagship",
		"price_cents":   20000,
		"duration_days": 30,
		"quota_bytes":   500 * 1024 * 1024 * 1024,
		"max_rules":     30,
		"speed_mbps":    500,
		"role_group_id": 1,
	}, "")
	if wP2.Code != http.StatusCreated {
		t.Fatalf("create P2 failed: %d %s", wP2.Code, wP2.Body.String())
	}
	var planFlag model.Plan
	_ = json.Unmarshal(wP2.Body.Bytes(), &planFlag)

	// Fund user@nexus.local with ¥500.00 (50000 cents)
	var demoUser model.User
	db.Where("email = ?", "user@nexus.local").First(&demoUser)
	db.Model(&model.User{}).Where("id = ?", demoUser.ID).Update("balance_cents", 50000)

	// 1. Admin creates a 20% off coupon with ¥30 cap (3000c), allowed ONLY on Flagship plan, per_user_limit=2
	wCpPct := doJSON(r, http.MethodPost, "/api/v1/admin/coupons", adminTok, map[string]any{
		"code":               "vip20",
		"name":               "旗舰 8 折券",
		"type":               "percent",
		"value":              20,
		"min_spend_cents":    10000,
		"max_discount_cents": 3000,
		"allowed_plan_ids":   fmt.Sprintf("%d", planFlag.ID),
		"max_uses":           10,
		"per_user_limit":     2,
		"active":             true,
	}, "")
	if wCpPct.Code != http.StatusCreated {
		t.Fatalf("create percent coupon failed: %d %s", wCpPct.Code, wCpPct.Body.String())
	}

	// Disallowed plan preview must fail (400)
	wWrongPlan := doJSON(r, http.MethodPost, "/api/v1/coupons/preview", userTok, map[string]any{
		"code":    "VIP20",
		"plan_id": planStd.ID,
		"scene":   "plan_purchase",
	}, "")
	if wWrongPlan.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for disallowed plan, got %d %s", wWrongPlan.Code, wWrongPlan.Body.String())
	}

	// Valid preview on Flagship (20% of 20000 = 4000, capped at 3000 -> payable 17000)
	wPreview := doJSON(r, http.MethodPost, "/api/v1/coupons/preview", userTok, map[string]any{
		"code":    "vip20",
		"plan_id": planFlag.ID,
		"scene":   "plan_purchase",
	}, "")
	if wPreview.Code != http.StatusOK {
		t.Fatalf("preview coupon failed: %d %s", wPreview.Code, wPreview.Body.String())
	}
	var pv struct {
		DiscountCents int64 `json:"discount_cents"`
		PayableCents  int64 `json:"payable_cents"`
	}
	_ = json.Unmarshal(wPreview.Body.Bytes(), &pv)
	if pv.DiscountCents != 3000 || pv.PayableCents != 17000 {
		t.Fatalf("expected discount=3000 payable=17000, got %+v", pv)
	}

	// Purchase Flagship plan with VIP20 -> balance 50000 - 17000 = 33000
	wBuy := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/plans/%d/purchase", planFlag.ID), userTok, map[string]any{
		"coupon_code": "vip20",
	}, "")
	if wBuy.Code != http.StatusOK {
		t.Fatalf("purchase with coupon failed: %d %s", wBuy.Code, wBuy.Body.String())
	}
	db.First(&demoUser, demoUser.ID)
	if demoUser.BalanceCents != 33000 {
		t.Fatalf("expected user balance 33000 after discounted purchase, got %d", demoUser.BalanceCents)
	}

	// Paid subscription reset with VIP20 -> balance 33000 - 17000 = 16000
	wResetPv := doJSON(r, http.MethodPost, "/api/v1/coupons/preview", userTok, map[string]any{
		"code":  "VIP20",
		"scene": "plan_reset",
	}, "")
	if wResetPv.Code != http.StatusOK {
		t.Fatalf("preview coupon for plan_reset failed: %d %s", wResetPv.Code, wResetPv.Body.String())
	}
	wReset := doJSON(r, http.MethodPost, "/api/v1/user/reset-subscription", userTok, map[string]any{
		"coupon_code": "VIP20",
	}, "")
	if wReset.Code != http.StatusOK {
		t.Fatalf("reset-subscription with coupon failed: %d %s", wReset.Code, wReset.Body.String())
	}
	db.First(&demoUser, demoUser.ID)
	if demoUser.BalanceCents != 16000 {
		t.Fatalf("expected user balance 16000 after discounted reset, got %d", demoUser.BalanceCents)
	}

	// Third attempt by same user must fail per_user_limit=2!
	wOverLimit := doJSON(r, http.MethodPost, "/api/v1/user/reset-subscription", userTok, map[string]any{
		"coupon_code": "VIP20",
	}, "")
	if wOverLimit.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when exceeding per_user_limit=2, got %d %s", wOverLimit.Code, wOverLimit.Body.String())
	}

	// 2. Expired coupon rejection & Fixed-amount coupon concurrency test (max_uses=1)
	wExpired := doJSON(r, http.MethodPost, "/api/v1/admin/coupons", adminTok, map[string]any{
		"code":    "OLD50",
		"name":    "已过期测试券",
		"type":    "fixed",
		"value":   1000,
		"ends_at": "2020-01-01",
		"active":  true,
	}, "")
	if wExpired.Code != http.StatusCreated {
		t.Fatalf("create expired coupon failed: %d %s", wExpired.Code, wExpired.Body.String())
	}
	wUseExpired := doJSON(r, http.MethodPost, "/api/v1/coupons/preview", userTok, map[string]any{
		"code":    "OLD50",
		"plan_id": planStd.ID,
	}, "")
	if wUseExpired.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired coupon, got %d", wUseExpired.Code)
	}

	wFlash := doJSON(r, http.MethodPost, "/api/v1/admin/coupons", adminTok, map[string]any{
		"code":            "FLASH15",
		"name":            "限量秒杀立减 ¥15",
		"type":            "fixed",
		"value":           1500,
		"min_spend_cents": 3000,
		"max_uses":        1,
		"per_user_limit":  1,
		"active":          true,
	}, "")
	if wFlash.Code != http.StatusCreated {
		t.Fatalf("create FLASH15 failed: %d %s", wFlash.Code, wFlash.Body.String())
	}

	// Race 6 concurrent purchases of Standard plan (¥50 - ¥15 = ¥35) using FLASH15 (max_uses=1)
	var okCount int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/plans/%d/purchase", planStd.ID), userTok, map[string]any{
				"coupon_code": "FLASH15",
			}, "")
			if w.Code == http.StatusOK {
				atomic.AddInt32(&okCount, 1)
			}
		}()
	}
	wg.Wait()
	if okCount != 1 {
		t.Fatalf("expected strictly 1 concurrent coupon claim to succeed, got %d", okCount)
	}

	// Verify BillingOrder stores coupon metadata
	var flashOrder model.BillingOrder
	if err := db.Where("coupon_code = ?", "FLASH15").First(&flashOrder).Error; err != nil {
		t.Fatalf("expected BillingOrder with coupon_code=FLASH15: %v", err)
	}
	if flashOrder.OriginalCents != 5000 || flashOrder.DiscountCents != 1500 || flashOrder.AmountCents != 3500 {
		t.Fatalf("unexpected BillingOrder coupon accounting: %+v", flashOrder)
	}
}

func TestPhase3AffiliateInviteCommissionTransferAndWithdrawal(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	inviterTok := login(t, r, "user@nexus.local", "user12345")

	// Enable registration + affiliate (15% commission, ¥10.00 min withdrawal)
	wCfg := doJSON(r, http.MethodPut, "/api/v1/admin/settings", adminTok, map[string]any{
		"allow_register":               true,
		"payment_enabled":              true,
		"affiliate_enabled":            true,
		"affiliate_commission_rate":    15.0,
		"affiliate_min_withdraw_cents": 1000,
	}, "")
	if wCfg.Code != http.StatusOK {
		t.Fatalf("enable affiliate settings failed: %d %s", wCfg.Code, wCfg.Body.String())
	}

	// 1. Inviter fetches overview & invite_code
	wOv0 := doJSON(r, http.MethodGet, "/api/v1/affiliate/overview", inviterTok, nil, "")
	if wOv0.Code != http.StatusOK {
		t.Fatalf("affiliate overview failed: %d %s", wOv0.Code, wOv0.Body.String())
	}
	var ov0 struct {
		InviteCode   string `json:"invite_code"`
		InviteURL    string `json:"invite_url"`
		InvitedCount int64  `json:"invited_count"`
	}
	_ = json.Unmarshal(wOv0.Body.Bytes(), &ov0)
	if ov0.InviteCode == "" || !strings.Contains(ov0.InviteURL, "ref="+ov0.InviteCode) {
		t.Fatalf("expected valid invite_code & invite_url, got %+v", ov0)
	}

	// 2. Registration with bogus invite_code must be rejected (400)
	wBadReg := doJSON(r, http.MethodPost, "/api/v1/auth/register", "", map[string]any{
		"email":       "badref@nexus.local",
		"password":    "pass123456",
		"invite_code": "INVALID999",
	}, "")
	if wBadReg.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid invite_code, got %d %s", wBadReg.Code, wBadReg.Body.String())
	}

	// 3. Valid registration bound to inviter's invite_code
	wReg := doJSON(r, http.MethodPost, "/api/v1/auth/register", "", map[string]any{
		"email":       "invitee@nexus.local",
		"password":    "pass123456",
		"invite_code": strings.ToLower(ov0.InviteCode),
	}, "")
	if wReg.Code != http.StatusCreated {
		t.Fatalf("register with invite_code failed: %d %s", wReg.Code, wReg.Body.String())
	}
	var regResp struct {
		Token string     `json:"token"`
		User  model.User `json:"user"`
	}
	_ = json.Unmarshal(wReg.Body.Bytes(), &regResp)
	inviteeTok := regResp.Token

	// 4. Invitee recharges ¥200.00 (20000c) via manual order -> Admin confirms -> Inviter gets 15% = 3000c
	wRech := doJSON(r, http.MethodPost, "/api/v1/orders/recharge", inviteeTok, map[string]any{
		"amount_cents": 20000,
		"gateway":      "manual",
	}, "")
	if wRech.Code != http.StatusCreated {
		t.Fatalf("create recharge order failed: %d %s", wRech.Code, wRech.Body.String())
	}
	var rechOrd model.BillingOrder
	_ = json.Unmarshal(wRech.Body.Bytes(), &rechOrd)

	wConfirm := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/orders/%d/confirm", rechOrd.ID), adminTok, nil, "")
	if wConfirm.Code != http.StatusOK {
		t.Fatalf("confirm recharge order failed: %d %s", wConfirm.Code, wConfirm.Body.String())
	}

	var inviter model.User
	db.Where("email = ?", "user@nexus.local").First(&inviter)
	if inviter.CommissionBalanceCents != 3000 || inviter.TotalCommissionCents != 3000 {
		t.Fatalf("expected inviter commission 3000c after ¥200 recharge, got avail=%d total=%d",
			inviter.CommissionBalanceCents, inviter.TotalCommissionCents)
	}

	// 5. Anti-double-commission check: Invitee buys a ¥100 (10000c) plan using that already-commissioned recharge balance!
	wPlan100 := doJSON(r, http.MethodPost, "/api/v1/admin/plans", adminTok, map[string]any{
		"name":          "P3-Aff-100",
		"price_cents":   10000,
		"duration_days": 30,
		"quota_bytes":   100 * 1024 * 1024 * 1024,
		"max_rules":     10,
		"speed_mbps":    100,
		"role_group_id": 1,
	}, "")
	var plan100 model.Plan
	_ = json.Unmarshal(wPlan100.Body.Bytes(), &plan100)

	wBuy1 := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/plans/%d/purchase", plan100.ID), inviteeTok, nil, "")
	if wBuy1.Code != http.StatusOK {
		t.Fatalf("invitee buy1 failed: %d %s", wBuy1.Code, wBuy1.Body.String())
	}
	db.First(&inviter, inviter.ID)
	if inviter.TotalCommissionCents != 3000 {
		t.Fatalf("expected ZERO double-commission when spending commissioned recharge balance, got total=%d", inviter.TotalCommissionCents)
	}

	// 6. Partial uncommissioned spend: Invitee redeems a ¥100 balance card (non-commissioned), now has ¥100 commissioned + ¥100 uncommissioned = ¥200.
	// Buying a ¥200 plan must settle commission ONLY on the uncommissioned ¥100 (15% = 1500c -> total 4500c)!
	wGenCard := doJSON(r, http.MethodPost, "/api/v1/admin/redeem/generate", adminTok, map[string]any{
		"count":         1,
		"balance_cents": 10000,
		"prefix":        "AF",
	}, "")
	var cards []model.RedeemCode
	_ = json.Unmarshal(wGenCard.Body.Bytes(), &cards)
	doJSON(r, http.MethodPost, "/api/v1/redeem", inviteeTok, map[string]any{"code": cards[0].Code}, "")

	wPlan200 := doJSON(r, http.MethodPost, "/api/v1/admin/plans", adminTok, map[string]any{
		"name":          "P3-Aff-200",
		"price_cents":   20000,
		"duration_days": 30,
		"quota_bytes":   200 * 1024 * 1024 * 1024,
		"max_rules":     15,
		"speed_mbps":    200,
		"role_group_id": 1,
	}, "")
	var plan200 model.Plan
	_ = json.Unmarshal(wPlan200.Body.Bytes(), &plan200)

	wBuy2 := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/plans/%d/purchase", plan200.ID), inviteeTok, nil, "")
	if wBuy2.Code != http.StatusOK {
		t.Fatalf("invitee buy2 failed: %d %s", wBuy2.Code, wBuy2.Body.String())
	}
	db.First(&inviter, inviter.ID)
	if inviter.CommissionBalanceCents != 4500 || inviter.TotalCommissionCents != 4500 {
		t.Fatalf("expected commission=4500c (3000 + 1500 on uncommissioned portion), got avail=%d total=%d",
			inviter.CommissionBalanceCents, inviter.TotalCommissionCents)
	}

	// 7. Concurrent withdrawal double-spend prevention (available 4500c, 4 goroutines requesting 3000c each -> strictly 1 succeeds)
	var wdSuccess int32
	var createdWdID uint64
	var wdMu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := doJSON(r, http.MethodPost, "/api/v1/affiliate/withdraw", inviterTok, map[string]any{
				"amount_cents": 3000,
				"method":       "usdt",
				"account":      "TTestWalletAddr123456789",
			}, "")
			if w.Code == http.StatusCreated {
				atomic.AddInt32(&wdSuccess, 1)
				var resp struct {
					Withdrawal model.AffiliateWithdrawal `json:"withdrawal"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &resp)
				wdMu.Lock()
				createdWdID = resp.Withdrawal.ID
				wdMu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wdSuccess != 1 || createdWdID == 0 {
		t.Fatalf("expected strictly 1 withdrawal request to succeed, got %d (id=%d)", wdSuccess, createdWdID)
	}
	db.First(&inviter, inviter.ID)
	if inviter.CommissionBalanceCents != 1500 {
		t.Fatalf("expected remaining commission 1500c after freezing 3000c, got %d", inviter.CommissionBalanceCents)
	}

	// 8. Admin rejects withdrawal -> 3000c refunded back to 4500c
	wReject := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/affiliate/withdrawals/%d/review", createdWdID), adminTok, map[string]any{
		"action": "reject",
		"remark": "地址格式核验退回",
	}, "")
	if wReject.Code != http.StatusOK {
		t.Fatalf("admin reject withdrawal failed: %d %s", wReject.Code, wReject.Body.String())
	}
	db.First(&inviter, inviter.ID)
	if inviter.CommissionBalanceCents != 4500 {
		t.Fatalf("expected commission refunded to 4500c on reject, got %d", inviter.CommissionBalanceCents)
	}

	// 9. Inviter submits 2500c withdrawal -> Admin approves; Inviter transfers remaining 2000c to account balance
	wWd2 := doJSON(r, http.MethodPost, "/api/v1/affiliate/withdraw", inviterTok, map[string]any{
		"amount_cents": 2500,
		"method":       "alipay",
		"account":      "inviter@alipay.example",
		"real_name":    "张三",
	}, "")
	if wWd2.Code != http.StatusCreated {
		t.Fatalf("second withdrawal failed: %d %s", wWd2.Code, wWd2.Body.String())
	}
	var wd2Resp struct {
		Withdrawal model.AffiliateWithdrawal `json:"withdrawal"`
	}
	_ = json.Unmarshal(wWd2.Body.Bytes(), &wd2Resp)
	wApprove := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/affiliate/withdrawals/%d/review", wd2Resp.Withdrawal.ID), adminTok, map[string]any{
		"action": "approve",
		"remark": "已打款",
	}, "")
	if wApprove.Code != http.StatusOK {
		t.Fatalf("approve withdrawal failed: %d %s", wApprove.Code, wApprove.Body.String())
	}

	balBefore := inviter.BalanceCents
	wTransfer := doJSON(r, http.MethodPost, "/api/v1/affiliate/transfer", inviterTok, map[string]any{
		"amount_cents": 0,
	}, "")
	if wTransfer.Code != http.StatusOK {
		t.Fatalf("transfer commission to balance failed: %d %s", wTransfer.Code, wTransfer.Body.String())
	}
	db.First(&inviter, inviter.ID)
	if inviter.CommissionBalanceCents != 0 || inviter.BalanceCents != balBefore+2000 {
		t.Fatalf("expected commission=0 and balance=%d after transfer, got comm=%d bal=%d",
			balBefore+2000, inviter.CommissionBalanceCents, inviter.BalanceCents)
	}
}

func TestPhase3SupportTicketsIDORWorkflowAndWebhookNotify(t *testing.T) {
	r, _, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	prevAllowPrivate := security.DefaultPolicy.AllowPrivateTargets
	security.DefaultPolicy.AllowPrivateTargets = true
	defer func() {
		security.DefaultPolicy.AllowPrivateTargets = prevAllowPrivate
	}()

	var mu sync.Mutex
	var events []string
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Event string `json:"event"`
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		mu.Lock()
		events = append(events, body.Event)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer webhookSrv.Close()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	user1Tok := login(t, r, "user@nexus.local", "user12345")

	// Enable registration + ticket webhook notifications
	wCfg := doJSON(r, http.MethodPut, "/api/v1/admin/settings", adminTok, map[string]any{
		"allow_register":          true,
		"notify_webhook_url":      webhookSrv.URL,
		"notify_on_ticket_events": true,
	}, "")
	if wCfg.Code != http.StatusOK {
		t.Fatalf("save settings failed: %d %s", wCfg.Code, wCfg.Body.String())
	}

	// Register a second regular user to verify strict IDOR isolation
	wReg2 := doJSON(r, http.MethodPost, "/api/v1/auth/register", "", map[string]any{
		"email":    "user2@nexus.local",
		"password": "user2pass123",
	}, "")
	if wReg2.Code != http.StatusCreated {
		t.Fatalf("register user2 failed: %d %s", wReg2.Code, wReg2.Body.String())
	}
	var reg2 struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(wReg2.Body.Bytes(), &reg2)
	user2Tok := reg2.Token

	// 1. User1 creates a forwarding rule
	wRule := doJSON(r, http.MethodPost, "/api/v1/rules", user1Tok, map[string]any{
		"name":            "HK-IEPL-Game",
		"mode":            "direct",
		"ingress_node_id": 1,
		"tunnel_line_id":  1,
		"engine":          "native",
		"protocol":        "tcp",
		"listen_port":     0,
		"targets":         []map[string]any{{"address": "1.1.1.1:443"}},
	}, "")
	if wRule.Code != http.StatusCreated {
		t.Fatalf("create rule failed: %d %s", wRule.Code, wRule.Body.String())
	}
	var user1Rule model.ForwardRule
	_ = json.Unmarshal(wRule.Body.Bytes(), &user1Rule)

	// 2. User2 attempting to bind User1's rule in a ticket must be blocked (403 Forbidden)
	wIDORRule := doJSON(r, http.MethodPost, "/api/v1/tickets", user2Tok, map[string]any{
		"subject":  "越权绑定他人规则测试",
		"category": "rule",
		"rule_id":  user1Rule.ID,
		"message":  "尝试绑定非本人名下规则",
	}, "")
	if wIDORRule.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when binding another user's rule, got %d %s", wIDORRule.Code, wIDORRule.Body.String())
	}

	// 3. User1 creates a valid ticket linked to user1Rule
	wCreateTk := doJSON(r, http.MethodPost, "/api/v1/tickets", user1Tok, map[string]any{
		"subject":  "深港专线晚高峰丢包排查",
		"category": "network",
		"priority": "high",
		"rule_id":  user1Rule.ID,
		"message":  "晚上 21:00 后延迟升高，麻烦协助看下入口节点情况。",
	}, "")
	if wCreateTk.Code != http.StatusCreated {
		t.Fatalf("create ticket failed: %d %s", wCreateTk.Code, wCreateTk.Body.String())
	}
	var tkResp struct {
		Ticket   model.SupportTicket   `json:"ticket"`
		Messages []model.TicketMessage `json:"messages"`
	}
	_ = json.Unmarshal(wCreateTk.Body.Bytes(), &tkResp)
	if tkResp.Ticket.Status != "open" || tkResp.Ticket.RuleID != user1Rule.ID || len(tkResp.Messages) != 1 {
		t.Fatalf("unexpected created ticket payload: %+v", tkResp)
	}
	ticketID := tkResp.Ticket.ID

	// 4. User2 attempting to read, reply to, or close User1's ticket must be blocked (403)
	if w := doJSON(r, http.MethodGet, fmt.Sprintf("/api/v1/tickets/%d", ticketID), user2Tok, nil, ""); w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on IDOR ticket detail, got %d", w.Code)
	}
	if w := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/tickets/%d/reply", ticketID), user2Tok, map[string]any{"message": "peek"}, ""); w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on IDOR ticket reply, got %d", w.Code)
	}
	if w := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/tickets/%d/close", ticketID), user2Tok, nil, ""); w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on IDOR ticket close, got %d", w.Code)
	}

	// 5. Admin replies -> status transitions to "answered"
	wAdminReply := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/tickets/%d/reply", ticketID), adminTok, map[string]any{
		"message": "已为您切换至低负载 BGP 入口，请重新测试延迟。",
	}, "")
	if wAdminReply.Code != http.StatusOK {
		t.Fatalf("admin reply failed: %d %s", wAdminReply.Code, wAdminReply.Body.String())
	}
	var adminReplyData struct {
		Ticket model.SupportTicket `json:"ticket"`
	}
	_ = json.Unmarshal(wAdminReply.Body.Bytes(), &adminReplyData)
	if adminReplyData.Ticket.Status != "answered" || adminReplyData.Ticket.LastReplyBy != "admin" {
		t.Fatalf("expected status=answered last_reply_by=admin, got %+v", adminReplyData.Ticket)
	}

	// 6. User1 follows up -> status transitions to "customer_reply"
	wUserReply := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/tickets/%d/reply", ticketID), user1Tok, map[string]any{
		"message": "已恢复到 12ms 稳定，非常感谢！",
	}, "")
	if wUserReply.Code != http.StatusOK {
		t.Fatalf("user follow-up reply failed: %d %s", wUserReply.Code, wUserReply.Body.String())
	}
	var userReplyData struct {
		Ticket model.SupportTicket `json:"ticket"`
	}
	_ = json.Unmarshal(wUserReply.Body.Bytes(), &userReplyData)
	if userReplyData.Ticket.Status != "customer_reply" {
		t.Fatalf("expected status=customer_reply, got %s", userReplyData.Ticket.Status)
	}

	// 7. Verify async Webhook received both ticket_created and ticket_replied!
	deadline := time.Now().Add(2 * time.Second)
	hasCreated, hasReplied := false, false
	for time.Now().Before(deadline) {
		mu.Lock()
		for _, ev := range events {
			if ev == "ticket_created" {
				hasCreated = true
			}
			if ev == "ticket_replied" {
				hasReplied = true
			}
		}
		mu.Unlock()
		if hasCreated && hasReplied {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !hasCreated || !hasReplied {
		t.Fatalf("expected both ticket_created and ticket_replied webhook notifications, got %v", events)
	}

	// 8. User1 closes ticket -> further user replies rejected (400), full detail has 3 messages
	wClose := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/tickets/%d/close", ticketID), user1Tok, nil, "")
	if wClose.Code != http.StatusOK {
		t.Fatalf("close ticket failed: %d %s", wClose.Code, wClose.Body.String())
	}
	wReplyClosed := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/tickets/%d/reply", ticketID), user1Tok, map[string]any{
		"message": "已关闭后再发",
	}, "")
	if wReplyClosed.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when user replies to closed ticket, got %d", wReplyClosed.Code)
	}

	wDetail := doJSON(r, http.MethodGet, fmt.Sprintf("/api/v1/tickets/%d", ticketID), user1Tok, nil, "")
	var finalDetail struct {
		Ticket   model.SupportTicket   `json:"ticket"`
		Messages []model.TicketMessage `json:"messages"`
	}
	_ = json.Unmarshal(wDetail.Body.Bytes(), &finalDetail)
	if finalDetail.Ticket.Status != "closed" || len(finalDetail.Messages) != 3 {
		t.Fatalf("expected closed ticket with 3 messages, got status=%s msgs=%d", finalDetail.Ticket.Status, len(finalDetail.Messages))
	}
}
