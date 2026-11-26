package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nexus-panel/internal/master/hub"
	"nexus-panel/internal/master/model"
	"nexus-panel/internal/master/service"
	"nexus-panel/pkg/protocol"
)

func TestPhase1TOTPAntiReplayAndConcurrentCAS(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	userTok := login(t, r, "user@nexus.local", "user12345")

	// Setup TOTP
	wSetup := doJSON(r, http.MethodPost, "/api/v1/user/totp/setup", userTok, nil, "")
	if wSetup.Code != http.StatusOK {
		t.Fatalf("setup totp failed: %d %s", wSetup.Code, wSetup.Body.String())
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(wSetup.Body.Bytes(), &setup)

	now := time.Now()
	prevStepCode, err := ComputeTOTPCode(setup.Secret, now.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	wEnable := doJSON(r, http.MethodPost, "/api/v1/user/totp/enable", userTok, map[string]string{"code": prevStepCode}, "")
	if wEnable.Code != http.StatusOK {
		t.Fatalf("enable totp failed: %d %s", wEnable.Code, wEnable.Body.String())
	}
	renewedTok := wEnable.Header().Get("X-Renewed-Token")
	if renewedTok == "" {
		t.Fatalf("expected X-Renewed-Token header on TOTP enablement")
	}

	// Re-enabling when already enabled must fail with 409 Conflict using post-2FA renewed token
	nextStepCode, _ := ComputeTOTPCode(setup.Secret, now.Add(30*time.Second))
	wReEnable := doJSON(r, http.MethodPost, "/api/v1/user/totp/enable", renewedTok, map[string]string{"code": nextStepCode}, "")
	if wReEnable.Code != http.StatusConflict {
		t.Fatalf("expected 409 when enabling already-enabled TOTP, got %d", wReEnable.Code)
	}

	// Using the already-consumed prevStepCode for login must fail (monotonic step enforcement)
	wOld := doJSON(r, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":     "user@nexus.local",
		"password":  "user12345",
		"totp_code": prevStepCode,
	}, "")
	if wOld.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for already-consumed older TOTP step, got %d", wOld.Code)
	}

	// Concurrent race: 8 goroutines simultaneously submit the current 30s code; exactly 1 must succeed!
	curCode, err := ComputeTOTPCode(setup.Secret, now)
	if err != nil {
		t.Fatal(err)
	}
	var okCount, failCount int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := doJSON(r, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
				"email":     "user@nexus.local",
				"password":  "user12345",
				"totp_code": curCode,
			}, nextIP())
			if w.Code == http.StatusOK {
				atomic.AddInt32(&okCount, 1)
			} else if w.Code == http.StatusUnauthorized {
				atomic.AddInt32(&failCount, 1)
			}
		}()
	}
	wg.Wait()
	if okCount != 1 || failCount != 7 {
		t.Fatalf("expected exactly 1 concurrent TOTP login success and 7 anti-replay rejections, got ok=%d fail=%d", okCount, failCount)
	}

	var u model.User
	db.Where("email = ?", "user@nexus.local").First(&u)
	if u.LastTOTPStep != now.UTC().Unix()/30 {
		t.Fatalf("expected last_totp_step=%d, got %d", now.UTC().Unix()/30, u.LastTOTPStep)
	}
}

func TestPhase1APIKeyPerIPFailureRateLimit(t *testing.T) {
	r, _, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	wGen := doJSON(r, http.MethodPost, "/api/v1/admin/settings/api-key", adminTok, nil, "")
	if wGen.Code != http.StatusOK {
		t.Fatalf("generate api key failed: %d", wGen.Code)
	}
	var keyResp struct {
		APIKey string `json:"api_key"`
	}
	_ = json.Unmarshal(wGen.Body.Bytes(), &keyResp)

	attackerIP := nextIP()
	throttled := false
	for i := 0; i < 15; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
		req.Header.Set("X-API-Key", fmt.Sprintf("zp_live_invalid_guess_%d", i))
		req.RemoteAddr = attackerIP
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatal("expected attacker IP to be rate-limited (429) after repeated X-API-Key failures")
	}

	// Attacker IP remains blocked even if it now presents Bearer zp_live_...
	reqBlocked := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	reqBlocked.Header.Set("Authorization", "Bearer "+keyResp.APIKey)
	reqBlocked.RemoteAddr = attackerIP
	wBlocked := httptest.NewRecorder()
	r.ServeHTTP(wBlocked, reqBlocked)
	if wBlocked.Code != http.StatusTooManyRequests {
		t.Fatalf("expected blocked IP to stay 429 on X-API-Key path, got %d", wBlocked.Code)
	}

	// Legitimate automation from a clean IP works across 30 consecutive calls without hitting rate limits
	cleanIP := nextIP()
	for i := 0; i < 30; i++ {
		reqOK := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
		reqOK.Header.Set("X-API-Key", keyResp.APIKey)
		reqOK.RemoteAddr = cleanIP
		wOK := httptest.NewRecorder()
		r.ServeHTTP(wOK, reqOK)
		if wOK.Code != http.StatusOK {
			t.Fatalf("valid X-API-Key from clean IP failed on iter %d: %d %s", i, wOK.Code, wOK.Body.String())
		}
	}
}

type chunkedLargeReader struct {
	remaining int
}

func (c *chunkedLargeReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > c.remaining {
		n = c.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = 'a'
	}
	c.remaining -= n
	return n, nil
}

func TestPhase1GlobalMaxBytesReader(t *testing.T) {
	r, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. Known Content-Length > 1 MiB -> immediate 413
	hugeJSON := `{"email":"` + strings.Repeat("x", int(MaxRequestBodyBytes)+1024) + `","password":"123"}`
	reqCL := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(hugeJSON))
	reqCL.Header.Set("Content-Type", "application/json")
	reqCL.RemoteAddr = nextIP()
	wCL := httptest.NewRecorder()
	r.ServeHTTP(wCL, reqCL)
	if wCL.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for Content-Length > 1MB, got %d: %s", wCL.Code, wCL.Body.String())
	}

	// 2. Chunked stream (ContentLength = -1) exceeding 1 MiB -> http.MaxBytesReader triggers 413
	chunkedStream := io.MultiReader(
		strings.NewReader(`{"email":"`),
		&chunkedLargeReader{remaining: int(MaxRequestBodyBytes) + 4096},
		strings.NewReader(`","password":"123"}`),
	)
	reqChunked := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", chunkedStream)
	reqChunked.ContentLength = -1
	reqChunked.Header.Set("Content-Type", "application/json")
	reqChunked.RemoteAddr = nextIP()
	wChunked := httptest.NewRecorder()
	r.ServeHTTP(wChunked, reqChunked)
	if wChunked.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for chunked body > 1MB, got %d: %s", wChunked.Code, wChunked.Body.String())
	}
}

func TestPhase1USDTWebhookAndExpiredOrderAutoClose(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	const usdtSecret = "usdt-hmac-secret-2026-prod"
	wCfg := doJSON(r, http.MethodPut, "/api/v1/admin/settings", adminTok, map[string]any{
		"payment_enabled":     true,
		"usdt_address":        "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
		"usdt_webhook_secret": usdtSecret,
	}, "")
	if wCfg.Code != http.StatusOK {
		t.Fatalf("configure usdt settings failed: %d %s", wCfg.Code, wCfg.Body.String())
	}
	// Secret must be masked in admin settings response and absent from public site-config
	if strings.Contains(wCfg.Body.String(), usdtSecret) {
		t.Fatalf("admin settings response leaked plaintext usdt_webhook_secret: %s", wCfg.Body.String())
	}
	wPub := doJSON(r, http.MethodGet, "/api/v1/site-config", "", nil, "")
	if strings.Contains(wPub.Body.String(), usdtSecret) || !strings.Contains(wPub.Body.String(), `"usdt_enabled":true`) {
		t.Fatalf("unexpected site-config payload: %s", wPub.Body.String())
	}

	var uBefore model.User
	db.Where("email = ?", "user@nexus.local").First(&uBefore)

	// Create two USDT recharge orders
	createUSDTOrder := func(cents int64) model.BillingOrder {
		w := doJSON(r, http.MethodPost, "/api/v1/orders/recharge", userTok, map[string]any{
			"amount_cents": cents,
			"gateway":      "usdt",
		}, "")
		if w.Code != http.StatusCreated {
			t.Fatalf("create usdt order failed: %d %s", w.Code, w.Body.String())
		}
		var o model.BillingOrder
		_ = json.Unmarshal(w.Body.Bytes(), &o)
		return o
	}
	order1 := createUSDTOrder(8800)
	order2 := createUSDTOrder(8800)
	orderExpired := createUSDTOrder(5000)

	sendUSDTWebhook := func(ts int64, sig string, payload map[string]any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(payload)
		if sig == "AUTO" {
			sig = ComputeUSDTWebhookSign(ts, raw, usdtSecret)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pay/usdt/notify", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-USDT-Timestamp", strconv.FormatInt(ts, 10))
		req.Header.Set("X-USDT-Signature", sig)
		req.RemoteAddr = nextIP()
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	nowTS := time.Now().Unix()

	// 1. Forged signature -> 403
	if w := sendUSDTWebhook(nowTS, strings.Repeat("a", 64), map[string]any{
		"order_no":     order1.OrderNo,
		"tx_hash":      "0xforged111",
		"amount_cents": 8800,
		"status":       "paid",
	}); w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for forged USDT signature, got %d %s", w.Code, w.Body.String())
	}

	// 2. Stale timestamp (> 300s) -> 403
	if w := sendUSDTWebhook(nowTS-600, "AUTO", map[string]any{
		"order_no":     order1.OrderNo,
		"tx_hash":      "0xstale111",
		"amount_cents": 8800,
		"status":       "paid",
	}); w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for stale USDT timestamp, got %d %s", w.Code, w.Body.String())
	}

	// 3. Amount mismatch -> 400
	if w := sendUSDTWebhook(nowTS, "AUTO", map[string]any{
		"order_no":     order1.OrderNo,
		"tx_hash":      "0xmismatch111",
		"amount_cents": 100,
		"status":       "paid",
	}); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for amount mismatch, got %d %s", w.Code, w.Body.String())
	}

	// 4. Valid signed callback -> 200 OK & credits 8800 cents
	const validTxHash = "0x9f8e7d6c5b4a3928172635445566778899aabbccddeeff001122334455667788"
	if w := sendUSDTWebhook(nowTS, "AUTO", map[string]any{
		"order_no":     order1.OrderNo,
		"tx_hash":      validTxHash,
		"amount_cents": 8800,
		"status":       "paid",
	}); w.Code != http.StatusOK {
		t.Fatalf("valid USDT callback failed: %d %s", w.Code, w.Body.String())
	}

	// 5. Idempotent replay of the exact same order + tx_hash -> 200 OK without double credit
	if w := sendUSDTWebhook(nowTS, "AUTO", map[string]any{
		"order_no":     order1.OrderNo,
		"tx_hash":      validTxHash,
		"amount_cents": 8800,
		"status":       "paid",
	}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"idempotent":true`) {
		t.Fatalf("expected idempotent 200 on USDT replay, got %d %s", w.Code, w.Body.String())
	}

	var uAfter model.User
	db.First(&uAfter, uBefore.ID)
	if uAfter.BalanceCents != uBefore.BalanceCents+8800 {
		t.Fatalf("expected balance %d after idempotent USDT callbacks, got %d", uBefore.BalanceCents+8800, uAfter.BalanceCents)
	}

	// 6. Replaying the same blockchain tx_hash against a DIFFERENT pending order -> 409 Conflict
	if w := sendUSDTWebhook(nowTS, "AUTO", map[string]any{
		"order_no":     order2.OrderNo,
		"tx_hash":      validTxHash,
		"amount_cents": 8800,
		"status":       "paid",
	}); w.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when reusing tx_hash across orders, got %d %s", w.Code, w.Body.String())
	}

	// 7. Expired unpaid order (> 30m) is rejected on late webhook AND auto-closed on list/scheduler
	staleCreated := time.Now().Add(-45 * time.Minute)
	db.Model(&model.BillingOrder{}).Where("id = ?", orderExpired.ID).Update("created_at", staleCreated)
	db.Model(&model.BillingOrder{}).Where("id = ?", order2.ID).Update("created_at", staleCreated)

	if w := sendUSDTWebhook(nowTS, "AUTO", map[string]any{
		"order_no":     orderExpired.OrderNo,
		"tx_hash":      "0xlatepayment999",
		"amount_cents": 5000,
		"status":       "paid",
	}); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when paying expired order, got %d %s", w.Code, w.Body.String())
	}

	// Listing orders triggers CloseExpiredOrders so order2 also transitions to cancelled
	wList := doJSON(r, http.MethodGet, "/api/v1/orders", userTok, nil, "")
	if wList.Code != http.StatusOK {
		t.Fatalf("list orders failed: %d", wList.Code)
	}
	var refreshedExpired, refreshedOrder2 model.BillingOrder
	db.First(&refreshedExpired, orderExpired.ID)
	db.First(&refreshedOrder2, order2.ID)
	if refreshedExpired.Status != "cancelled" || refreshedOrder2.Status != "cancelled" {
		t.Fatalf("expected expired pending orders to transition to cancelled, got %s and %s", refreshedExpired.Status, refreshedOrder2.Status)
	}
}

func TestPhase1SecretMaskingAndHostSanitization(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")

	// Save secrets, then save another field sending masked "********" sentinel -> original secrets must remain intact in DB
	w1 := doJSON(r, http.MethodPut, "/api/v1/admin/settings", adminTok, map[string]any{
		"epay_key":                  "real-epay-secret",
		"usdt_webhook_secret":       "real-usdt-secret",
		"notify_telegram_bot_token": "123456:real-tg-secret",
	}, "")
	if w1.Code != http.StatusOK {
		t.Fatalf("save secrets failed: %d", w1.Code)
	}
	var getCfg model.SystemConfig
	wGet := doJSON(r, http.MethodGet, "/api/v1/admin/settings", adminTok, nil, "")
	_ = json.Unmarshal(wGet.Body.Bytes(), &getCfg)
	if getCfg.EpayKey != maskedSecretPlaceholder || getCfg.USDTWebhookSecret != maskedSecretPlaceholder || getCfg.NotifyTelegramBotToken != maskedSecretPlaceholder {
		t.Fatalf("expected secrets to be masked as %q, got %+v", maskedSecretPlaceholder, getCfg)
	}

	// Round-trip save with masked placeholders must preserve real secrets in DB
	w2 := doJSON(r, http.MethodPut, "/api/v1/admin/settings", adminTok, map[string]any{
		"site_name":                 "Hardened Panel",
		"epay_key":                  maskedSecretPlaceholder,
		"usdt_webhook_secret":       maskedSecretPlaceholder,
		"notify_telegram_bot_token": maskedSecretPlaceholder,
	}, "")
	if w2.Code != http.StatusOK {
		t.Fatalf("round-trip save failed: %d", w2.Code)
	}
	var dbCfg model.SystemConfig
	db.First(&dbCfg, 1)
	if dbCfg.EpayKey != "real-epay-secret" || dbCfg.USDTWebhookSecret != "real-usdt-secret" || dbCfg.NotifyTelegramBotToken != "123456:real-tg-secret" {
		t.Fatalf("masked round-trip overwrote real DB secrets: %+v", dbCfg)
	}

	// Admin GET /api/v1/nodes must not expose node secret_token
	wNodes := doJSON(r, http.MethodGet, "/api/v1/nodes", adminTok, nil, "")
	if strings.Contains(wNodes.Body.String(), "secret_token") {
		t.Fatalf("GET /api/v1/nodes leaked secret_token: %s", wNodes.Body.String())
	}

	// Host header injection on install-cmd must be neutralized by sanitizeRequestHost
	reqHost := httptest.NewRequest(http.MethodGet, "/api/v1/admin/nodes/1/install-cmd", nil)
	reqHost.Header.Set("Authorization", "Bearer "+adminTok)
	reqHost.Host = "evil.example.com/$(touch /tmp/pwned)"
	reqHost.RemoteAddr = nextIP()
	wHost := httptest.NewRecorder()
	r.ServeHTTP(wHost, reqHost)
	if wHost.Code != http.StatusOK || strings.Contains(wHost.Body.String(), "pwned") || !strings.Contains(wHost.Body.String(), "127.0.0.1:8080") {
		t.Fatalf("Host header injection was not sanitized: %d %s", wHost.Code, wHost.Body.String())
	}
}

func TestPhase1TrafficDeltaBoundsAndSafeScale(t *testing.T) {
	_, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	orch := service.NewOrchestrator(db, hub.NewAgentHub(db))

	var user model.User
	db.Where("email = ?", "user@nexus.local").First(&user)
	// Raise user quota so cutoff doesn't mask exact billing verification
	db.Model(&model.User{}).Where("id = ?", user.ID).Update("quota_bytes", int64(100)<<40)

	rule := model.ForwardRule{
		UserID:        user.ID,
		Name:          "BoundsRule",
		Mode:          "direct",
		TunnelLineID:  1,
		IngressNodeID: 1,
		Engine:        protocol.EngineNative,
		Protocol:      "tcp",
		ListenPort:    25501,
		TargetsJSON:   `[{"address":"1.1.1.1:443"}]`,
		Enabled:       true,
		Status:        "running",
	}
	if err := db.Create(&rule).Error; err != nil {
		t.Fatal(err)
	}

	// Submit report containing:
	// - negative upload (-5000) -> clamped to 0
	// - oversized download (50 GiB > 10 GiB maxDeltaBytes) -> clamped to 10 GiB
	// - duplicate (RuleID, Role) entry in same report -> ignored so malicious agent cannot bypass per-rule cap by repeating
	orch.HandleTrafficReport(1, protocol.TrafficReportPayload{
		NodeID:    1,
		Timestamp: time.Now().Unix(),
		Deltas: []protocol.RuleTrafficDelta{
			{
				RuleID:      rule.ID,
				Role:        protocol.RoleRelay,
				Engine:      protocol.EngineNative,
				UploadBytes: -5000,
				DownBytes:   50 << 30,
			},
			{
				RuleID:      rule.ID,
				Role:        protocol.RoleRelay,
				Engine:      protocol.EngineNative,
				UploadBytes: 5 << 30,
				DownBytes:   5 << 30,
			},
		},
	})

	var gotRule model.ForwardRule
	db.First(&gotRule, rule.ID)
	const tenGiB = int64(10) << 30
	if gotRule.UploadBytes != 0 || gotRule.DownBytes != tenGiB {
		t.Fatalf("expected clamped upload=0 and down=10GiB (duplicate dropped), got up=%d down=%d", gotRule.UploadBytes, gotRule.DownBytes)
	}
}
