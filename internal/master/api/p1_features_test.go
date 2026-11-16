package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"nexus-panel/internal/agent/security"
	"nexus-panel/internal/master/model"
	"nexus-panel/pkg/protocol"
)

func TestP1BillingOrdersAndRechargeNotify(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	// 1. Admin configures EPay gateway
	const epaySecret = "epay-test-secret-key-2026"
	wCfg := doJSON(r, http.MethodPut, "/api/v1/admin/settings", adminTok, map[string]any{
		"payment_enabled": true,
		"epay_url":        "https://epay.example.com",
		"epay_pid":        "10088",
		"epay_key":        epaySecret,
		"usdt_address":    "TTestUSDTAddress999",
		"recharge_notice": "支持支付宝/微信实时回调到账",
	}, "")
	if wCfg.Code != http.StatusOK {
		t.Fatalf("update payment settings failed: %d %s", wCfg.Code, wCfg.Body.String())
	}

	// Public /api/v1/site-config must NEVER leak epay_key
	wPublicCfg := doJSON(r, http.MethodGet, "/api/v1/site-config", "", nil, "")
	if wPublicCfg.Code != http.StatusOK {
		t.Fatalf("get site-config failed: %d", wPublicCfg.Code)
	}
	if strings.Contains(wPublicCfg.Body.String(), epaySecret) {
		t.Fatalf("SECURITY LEAK: site-config leaked epay_key: %s", wPublicCfg.Body.String())
	}

	// 2. User creates an EPay recharge order for ¥100.00 (10000 cents)
	var uBefore model.User
	db.Where("email = ?", "user@nexus.local").First(&uBefore)

	wOrder := doJSON(r, http.MethodPost, "/api/v1/orders/recharge", userTok, map[string]any{
		"amount_cents": 10000,
		"gateway":      "epay",
		"pay_type":     "alipay",
	}, "")
	if wOrder.Code != http.StatusCreated {
		t.Fatalf("create recharge order failed: %d %s", wOrder.Code, wOrder.Body.String())
	}
	var order model.BillingOrder
	if err := json.Unmarshal(wOrder.Body.Bytes(), &order); err != nil {
		t.Fatalf("unmarshal order: %v", err)
	}
	if order.Status != "pending" || !strings.HasPrefix(order.PayURL, "https://epay.example.com/submit.php?") {
		t.Fatalf("unexpected recharge order: %+v", order)
	}

	// 3. Forged EPay callback must be rejected (403)
	forgedReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/pay/epay/notify?pid=10088&out_trade_no=%s&trade_no=EP001&type=alipay&money=100.00&trade_status=TRADE_SUCCESS&sign=deadbeef", order.OrderNo), nil)
	forgedW := httptest.NewRecorder()
	r.ServeHTTP(forgedW, forgedReq)
	if forgedW.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for forged sign, got %d %s", forgedW.Code, forgedW.Body.String())
	}

	// 4. Amount mismatch callback (signed for 1.00 instead of 100.00) must be rejected (400)
	mismatchParams := map[string]string{
		"pid":          "10088",
		"out_trade_no": order.OrderNo,
		"trade_no":     "EP002",
		"type":         "alipay",
		"money":        "1.00",
		"trade_status": "TRADE_SUCCESS",
	}
	mismatchSign := computeEpaySign(mismatchParams, epaySecret)
	mismatchVals := url.Values{}
	for k, v := range mismatchParams {
		mismatchVals.Set(k, v)
	}
	mismatchVals.Set("sign", mismatchSign)
	mismatchVals.Set("sign_type", "MD5")
	mismatchReq := httptest.NewRequest(http.MethodGet, "/api/v1/pay/epay/notify?"+mismatchVals.Encode(), nil)
	mismatchW := httptest.NewRecorder()
	r.ServeHTTP(mismatchW, mismatchReq)
	if mismatchW.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for amount mismatch callback, got %d %s", mismatchW.Code, mismatchW.Body.String())
	}

	// 5. Valid EPay callback credits user balance and transitions order to paid
	validParams := map[string]string{
		"pid":          "10088",
		"out_trade_no": order.OrderNo,
		"trade_no":     "EP20261116001",
		"type":         "alipay",
		"money":        "100.00",
		"trade_status": "TRADE_SUCCESS",
	}
	validSign := computeEpaySign(validParams, epaySecret)
	validVals := url.Values{}
	for k, v := range validParams {
		validVals.Set(k, v)
	}
	validVals.Set("sign", validSign)
	validVals.Set("sign_type", "MD5")

	notifyReq := httptest.NewRequest(http.MethodGet, "/api/v1/pay/epay/notify?"+validVals.Encode(), nil)
	notifyW := httptest.NewRecorder()
	r.ServeHTTP(notifyW, notifyReq)
	if notifyW.Code != http.StatusOK || notifyW.Body.String() != "success" {
		t.Fatalf("valid epay notify failed: %d %s", notifyW.Code, notifyW.Body.String())
	}

	// Replay the same callback and verify idempotency (no double credit)
	replayReq := httptest.NewRequest(http.MethodGet, "/api/v1/pay/epay/notify?"+validVals.Encode(), nil)
	replayW := httptest.NewRecorder()
	r.ServeHTTP(replayW, replayReq)
	if replayW.Code != http.StatusOK || replayW.Body.String() != "success" {
		t.Fatalf("replay epay notify failed: %d %s", replayW.Code, replayW.Body.String())
	}

	var uAfter model.User
	db.Where("email = ?", "user@nexus.local").First(&uAfter)
	if uAfter.BalanceCents != uBefore.BalanceCents+10000 {
		t.Fatalf("expected balance %d after single credit, got %d", uBefore.BalanceCents+10000, uAfter.BalanceCents)
	}

	// 6. Manual/USDT order + admin manual confirmation
	wManual := doJSON(r, http.MethodPost, "/api/v1/orders/recharge", userTok, map[string]any{
		"amount_cents": 5000,
		"gateway":      "usdt",
	}, "")
	if wManual.Code != http.StatusCreated {
		t.Fatalf("create usdt order failed: %d %s", wManual.Code, wManual.Body.String())
	}
	var manualOrder model.BillingOrder
	_ = json.Unmarshal(wManual.Body.Bytes(), &manualOrder)

	wConfirm := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/orders/%d/confirm", manualOrder.ID), adminTok, nil, "")
	if wConfirm.Code != http.StatusOK {
		t.Fatalf("admin confirm order failed: %d %s", wConfirm.Code, wConfirm.Body.String())
	}

	// 7. Purchase plan and check GET /api/v1/orders contains recharge & plan_purchase records
	wBuy := doJSON(r, http.MethodPost, "/api/v1/plans/1/purchase", userTok, nil, "")
	if wBuy.Code != http.StatusOK {
		t.Fatalf("purchase plan #1 failed: %d %s", wBuy.Code, wBuy.Body.String())
	}

	wList := doJSON(r, http.MethodGet, "/api/v1/orders", userTok, nil, "")
	if wList.Code != http.StatusOK {
		t.Fatalf("list user orders failed: %d %s", wList.Code, wList.Body.String())
	}
	var orders []model.BillingOrder
	if err := json.Unmarshal(wList.Body.Bytes(), &orders); err != nil {
		t.Fatalf("unmarshal orders: %v", err)
	}
	if len(orders) < 3 {
		t.Fatalf("expected at least 3 orders (2 recharges + 1 plan_purchase), got %d", len(orders))
	}
}

func TestP1AlertNotificationWebhook(t *testing.T) {
	r, _, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")

	type receivedWebhook struct {
		Event string `json:"event"`
		Title string `json:"title"`
		Text  string `json:"text"`
	}
	var (
		mu       sync.Mutex
		received []receivedWebhook
	)
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body receivedWebhook
		_ = json.NewDecoder(req.Body).Decode(&body)
		mu.Lock()
		received = append(received, body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer webhookSrv.Close()

	// 1. SSRF check: when AllowPrivateTargets is false, loopback webhook URL must be rejected
	prevAllowPrivate := security.DefaultPolicy.AllowPrivateTargets
	security.DefaultPolicy.AllowPrivateTargets = false
	defer func() {
		security.DefaultPolicy.AllowPrivateTargets = prevAllowPrivate
	}()

	wBlocked := doJSON(r, http.MethodPut, "/api/v1/admin/settings", adminTok, map[string]any{
		"notify_webhook_url": webhookSrv.URL,
	}, "")
	if wBlocked.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when setting loopback webhook URL with AllowPrivateTargets=false, got %d %s", wBlocked.Code, wBlocked.Body.String())
	}

	// 2. Allow private targets for local test server and configure webhook + event toggles
	security.DefaultPolicy.AllowPrivateTargets = true
	wSave := doJSON(r, http.MethodPut, "/api/v1/admin/settings", adminTok, map[string]any{
		"notify_webhook_url":        webhookSrv.URL,
		"notify_telegram_bot_token": "999999:SECRET_TG_BOT_TOKEN",
		"notify_telegram_chat_id":   "",
		"notify_on_node_events":     true,
		"notify_on_quota_events":    true,
	}, "")
	if wSave.Code != http.StatusOK {
		t.Fatalf("save webhook settings failed: %d %s", wSave.Code, wSave.Body.String())
	}

	// Public /api/v1/site-config must NEVER leak webhook URL or telegram bot token
	wPub := doJSON(r, http.MethodGet, "/api/v1/site-config", "", nil, "")
	if strings.Contains(wPub.Body.String(), "SECRET_TG_BOT_TOKEN") || strings.Contains(wPub.Body.String(), webhookSrv.URL) {
		t.Fatalf("SECURITY LEAK: site-config leaked notification credentials: %s", wPub.Body.String())
	}

	// 3. Trigger POST /api/v1/admin/settings/test-notify and verify webhook delivery
	wTest := doJSON(r, http.MethodPost, "/api/v1/admin/settings/test-notify", adminTok, nil, "")
	if wTest.Code != http.StatusOK {
		t.Fatalf("test-notify failed: %d %s", wTest.Code, wTest.Body.String())
	}

	mu.Lock()
	count := len(received)
	var firstEvent string
	if count > 0 {
		firstEvent = received[0].Event
	}
	mu.Unlock()
	if count != 1 || firstEvent != "test_alert" {
		t.Fatalf("expected 1 test_alert webhook, got count=%d firstEvent=%q", count, firstEvent)
	}

	// 4. Create an active rule for user@nexus.local, then trigger quota cutoff and verify webhook alert
	userTok := login(t, r, "user@nexus.local", "user12345")
	wRule := doJSON(r, http.MethodPost, "/api/v1/rules", userTok, map[string]any{
		"name":            "AlertTestRule",
		"tunnel_line_id":  1,
		"ingress_node_id": 1,
		"protocol":        "tcp",
		"listen_port":     20199,
		"targets":         []map[string]any{{"address": "1.1.1.1:443"}},
	}, "")
	if wRule.Code != http.StatusCreated {
		t.Fatalf("create user rule failed: %d %s", wRule.Code, wRule.Body.String())
	}

	wQuota := doJSON(r, http.MethodPut, "/api/v1/admin/users/2", adminTok, map[string]any{
		"quota_bytes": 1024 * 1024 * 1024,
		"used_bytes":  2 * 1024 * 1024 * 1024,
	}, "")
	if wQuota.Code != http.StatusOK {
		t.Fatalf("update user quota failed: %d %s", wQuota.Code, wQuota.Body.String())
	}

	deadline := time.Now().Add(2 * time.Second)
	foundQuotaAlert := false
	for time.Now().Before(deadline) {
		mu.Lock()
		for _, item := range received {
			if item.Event == "user_quota_exceeded" {
				foundQuotaAlert = true
				break
			}
		}
		mu.Unlock()
		if foundQuotaAlert {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !foundQuotaAlert {
		t.Fatalf("expected async user_quota_exceeded webhook alert to be delivered")
	}
}

func TestP1AgentVersionAndRemoteUpgrade(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")

	// 1. Offline node upgrade must return 400
	wOffline := doJSON(r, http.MethodPost, "/api/v1/admin/nodes/1/upgrade", adminTok, map[string]any{
		"target_version": "1.2.5-sec",
	}, "")
	if wOffline.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for offline node upgrade, got %d %s", wOffline.Code, wOffline.Body.String())
	}

	// 2. Connect an Agent for Node #1 via WebSocket and register with custom version "1.1.9-custom"
	var node1 model.Node
	if err := db.First(&node1, 1).Error; err != nil {
		t.Fatalf("load node #1: %v", err)
	}

	tsSrv := httptest.NewServer(r)
	defer tsSrv.Close()
	wsURL := "ws" + strings.TrimPrefix(tsSrv.URL, "http") + "/api/v1/agent/ws"

	nowTS := time.Now().Unix()
	nonce := protocol.GenerateNonce()
	sig := protocol.ComputeHandshakeAuth(node1.ID, nowTS, nonce, node1.SecretToken)
	hdr := http.Header{}
	hdr.Set("X-Node-ID", fmt.Sprintf("%d", node1.ID))
	hdr.Set("X-Auth-Timestamp", fmt.Sprintf("%d", nowTS))
	hdr.Set("X-Auth-Nonce", nonce)
	hdr.Set("X-Auth-Signature", sig)

	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		t.Fatalf("dial agent ws: %v", err)
	}
	defer wsConn.Close()

	regEnv, err := protocol.SignEnvelope(protocol.MsgAgentRegister, protocol.AgentRegisterPayload{
		NodeID:           node1.ID,
		AgentVersion:     "1.1.9-custom",
		OS:               "linux",
		Arch:             "amd64",
		SupportedEngines: []protocol.EngineType{protocol.EngineNative},
	}, node1.SecretToken)
	if err != nil {
		t.Fatalf("sign register env: %v", err)
	}
	if err := wsConn.WriteJSON(regEnv); err != nil {
		t.Fatalf("send register env: %v", err)
	}

	upgradeCh := make(chan protocol.UpgradeAgentPayload, 4)
	agentGuard := protocol.NewReplayGuard()
	go func() {
		for {
			_, raw, rerr := wsConn.ReadMessage()
			if rerr != nil {
				return
			}
			env, payloadBytes, verr := protocol.VerifyEnvelope(raw, node1.SecretToken, agentGuard)
			if verr == nil && env.Type == protocol.MsgUpgradeAgent {
				var up protocol.UpgradeAgentPayload
				if json.Unmarshal(payloadBytes, &up) == nil {
					upgradeCh <- up
				}
			}
		}
	}()

	// Wait briefly for registration to be processed and check /api/v1/nodes reports agent_version = "1.1.9-custom"
	time.Sleep(80 * time.Millisecond)
	wNodes := doJSON(r, http.MethodGet, "/api/v1/nodes", adminTok, nil, "")
	if wNodes.Code != http.StatusOK {
		t.Fatalf("list nodes failed: %d", wNodes.Code)
	}
	var nodeList []model.Node
	_ = json.Unmarshal(wNodes.Body.Bytes(), &nodeList)
	if len(nodeList) == 0 || nodeList[0].AgentVersion != "1.1.9-custom" {
		t.Fatalf("expected node #1 agent_version '1.1.9-custom', got %+v", nodeList)
	}

	// 3. Trigger single-node remote upgrade and verify signed MsgUpgradeAgent is received by Agent
	wUp := doJSON(r, http.MethodPost, "/api/v1/admin/nodes/1/upgrade", adminTok, map[string]any{
		"target_version": "1.2.5-sec",
	}, "")
	if wUp.Code != http.StatusOK {
		t.Fatalf("upgrade node #1 failed: %d %s", wUp.Code, wUp.Body.String())
	}

	select {
	case up := <-upgradeCh:
		if up.TargetVersion != "1.2.5-sec" {
			t.Fatalf("unexpected upgrade target_version: %+v", up)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for signed MsgUpgradeAgent frame on agent websocket")
	}

	// 4. Trigger batch-upgrade for all online nodes
	wBatchUp := doJSON(r, http.MethodPost, "/api/v1/admin/nodes/batch-upgrade", adminTok, map[string]any{
		"target_version": "1.3.0-sec",
	}, "")
	if wBatchUp.Code != http.StatusOK {
		t.Fatalf("batch-upgrade nodes failed: %d %s", wBatchUp.Code, wBatchUp.Body.String())
	}
	select {
	case up := <-upgradeCh:
		if up.TargetVersion != "1.3.0-sec" {
			t.Fatalf("unexpected batch upgrade target_version: %+v", up)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for batch MsgUpgradeAgent frame")
	}
}


