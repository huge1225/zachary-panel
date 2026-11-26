package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nexus-panel/internal/agent/engine"
	"nexus-panel/internal/agent/security"
	"nexus-panel/internal/master/model"
	"nexus-panel/pkg/protocol"
)

func TestP2AuditLogsAndSQLiteHotBackup(t *testing.T) {
	r, _, _ := setupTestServerWithDB(t)
	adminToken := loginAndGetToken(t, r, "admin@nexus.local", "admin123")
	userToken := loginAndGetToken(t, r, "user@nexus.local", "user12345")

	// 1. Non-admin should be rejected from audit logs and SQLite backup
	reqUserAudit := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs", nil)
	reqUserAudit.Header.Set("Authorization", "Bearer "+userToken)
	wUserAudit := httptest.NewRecorder()
	r.ServeHTTP(wUserAudit, reqUserAudit)
	if wUserAudit.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin audit logs, got %d", wUserAudit.Code)
	}

	reqUserBackup := httptest.NewRequest(http.MethodGet, "/api/v1/admin/backup/sqlite", nil)
	reqUserBackup.Header.Set("Authorization", "Bearer "+userToken)
	wUserBackup := httptest.NewRecorder()
	r.ServeHTTP(wUserBackup, reqUserBackup)
	if wUserBackup.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin sqlite backup, got %d", wUserBackup.Code)
	}

	// 2. Trigger an admin settings update and redeem code generation to populate audit logs
	settingsPayload, _ := json.Marshal(map[string]any{
		"site_name": "Zachary Panel Pro",
	})
	reqSet := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings", bytes.NewReader(settingsPayload))
	reqSet.Header.Set("Authorization", "Bearer "+adminToken)
	reqSet.Header.Set("Content-Type", "application/json")
	wSet := httptest.NewRecorder()
	r.ServeHTTP(wSet, reqSet)
	if wSet.Code != http.StatusOK {
		t.Fatalf("expected 200 updating settings, got %d: %s", wSet.Code, wSet.Body.String())
	}

	// 3. Export SQLite hot backup via VACUUM INTO
	reqBackup := httptest.NewRequest(http.MethodGet, "/api/v1/admin/backup/sqlite", nil)
	reqBackup.Header.Set("Authorization", "Bearer "+adminToken)
	wBackup := httptest.NewRecorder()
	r.ServeHTTP(wBackup, reqBackup)
	if wBackup.Code != http.StatusOK {
		t.Fatalf("expected 200 exporting sqlite backup, got %d: %s", wBackup.Code, wBackup.Body.String())
	}
	backupBytes := wBackup.Body.Bytes()
	if len(backupBytes) < 16 || string(backupBytes[:16]) != "SQLite format 3\x00" {
		t.Fatalf("expected valid SQLite3 header, got len=%d", len(backupBytes))
	}
	if !strings.Contains(wBackup.Header().Get("Content-Disposition"), "zachary-panel-backup-") {
		t.Fatalf("unexpected Content-Disposition header: %s", wBackup.Header().Get("Content-Disposition"))
	}

	// 4. Query audit logs and verify login, settings.update, and system.backup_sqlite are recorded
	reqLogs := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs", nil)
	reqLogs.Header.Set("Authorization", "Bearer "+adminToken)
	wLogs := httptest.NewRecorder()
	r.ServeHTTP(wLogs, reqLogs)
	if wLogs.Code != http.StatusOK {
		t.Fatalf("expected 200 listing audit logs, got %d: %s", wLogs.Code, wLogs.Body.String())
	}
	var logs []model.AuditLog
	if err := json.Unmarshal(wLogs.Body.Bytes(), &logs); err != nil {
		t.Fatalf("unmarshal audit logs failed: %v", err)
	}
	if len(logs) < 3 {
		t.Fatalf("expected at least 3 audit logs, got %d", len(logs))
	}

	seenActions := map[string]bool{}
	for _, l := range logs {
		seenActions[l.Action] = true
	}
	for _, want := range []string{"user.login", "admin.update_settings", "admin.backup_sqlite"} {
		if !seenActions[want] {
			t.Fatalf("expected audit action %q to be recorded, seen=%v", want, seenActions)
		}
	}

	// 5. Filter audit logs by action
	reqFilter := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs?action=admin.backup_sqlite", nil)
	reqFilter.Header.Set("Authorization", "Bearer "+adminToken)
	wFilter := httptest.NewRecorder()
	r.ServeHTTP(wFilter, reqFilter)
	if wFilter.Code != http.StatusOK {
		t.Fatalf("expected 200 filtering audit logs, got %d", wFilter.Code)
	}
	var filtered []model.AuditLog
	if err := json.Unmarshal(wFilter.Body.Bytes(), &filtered); err != nil {
		t.Fatalf("unmarshal filtered audit logs failed: %v", err)
	}
	if len(filtered) != 1 || filtered[0].Action != "admin.backup_sqlite" {
		t.Fatalf("expected 1 backup audit log, got %+v", filtered)
	}
}

func TestP2RuleACLHealthCheckAndPortRange(t *testing.T) {
	r, _, _ := setupTestServerWithDB(t)
	adminToken := loginAndGetToken(t, r, "admin@nexus.local", "admin123")

	// 1. Reject invalid CIDR when creating a rule
	badACLBody, _ := json.Marshal(map[string]any{
		"name":           "bad-acl-rule",
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"targets":        []map[string]any{{"address": "1.1.1.1:443"}},
		"access_mode":    "allow",
		"access_cidrs":   "999.999.999.999/24",
	})
	reqBad := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(badACLBody))
	reqBad.Header.Set("Authorization", "Bearer "+adminToken)
	reqBad.Header.Set("Content-Type", "application/json")
	wBad := httptest.NewRecorder()
	r.ServeHTTP(wBad, reqBad)
	if wBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid CIDR, got %d: %s", wBad.Code, wBad.Body.String())
	}

	// 2. Create a rule with valid ACL + custom speed_mbps and verify EffectiveEngine falls back to native
	goodACLBody, _ := json.Marshal(map[string]any{
		"name":           "acl-speed-rule",
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"targets":        []map[string]any{{"address": "1.1.1.1:443"}},
		"speed_mbps":     50,
		"access_mode":    "allow",
		"access_cidrs":   "198.51.100.0/24, 203.0.113.7",
	})
	reqGood := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(goodACLBody))
	reqGood.Header.Set("Authorization", "Bearer "+adminToken)
	reqGood.Header.Set("Content-Type", "application/json")
	wGood := httptest.NewRecorder()
	r.ServeHTTP(wGood, reqGood)
	if wGood.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating ACL rule, got %d: %s", wGood.Code, wGood.Body.String())
	}
	var createdRule model.ForwardRule
	if err := json.Unmarshal(wGood.Body.Bytes(), &createdRule); err != nil {
		t.Fatalf("unmarshal created rule failed: %v", err)
	}
	if createdRule.AccessMode != "allow" || createdRule.AccessCIDRs != "198.51.100.0/24,203.0.113.7" {
		t.Fatalf("unexpected ACL fields: mode=%q cidrs=%q", createdRule.AccessMode, createdRule.AccessCIDRs)
	}
	if createdRule.EffectiveEngine != protocol.EngineNative {
		t.Fatalf("expected EffectiveEngine=native when ACL is active, got %q", createdRule.EffectiveEngine)
	}

	// 3. Batch create rules with port_range expansion (20211-20213 -> 1.1.1.1:30211-30213)
	batchBody, _ := json.Marshal(map[string]any{
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"items": []map[string]any{
			{
				"name":       "游戏端口段",
				"port_range": "20211-20213",
				"targets":    []map[string]any{{"address": "1.1.1.1:30211-30213"}},
			},
		},
	})
	reqBatch := httptest.NewRequest(http.MethodPost, "/api/v1/rules/batch", bytes.NewReader(batchBody))
	reqBatch.Header.Set("Authorization", "Bearer "+adminToken)
	reqBatch.Header.Set("Content-Type", "application/json")
	wBatch := httptest.NewRecorder()
	r.ServeHTTP(wBatch, reqBatch)
	if wBatch.Code != http.StatusCreated {
		t.Fatalf("expected 201 batch creating port-range rules, got %d: %s", wBatch.Code, wBatch.Body.String())
	}
	var batchCreated []model.ForwardRule
	if err := json.Unmarshal(wBatch.Body.Bytes(), &batchCreated); err != nil {
		t.Fatalf("unmarshal batch rules failed: %v", err)
	}
	if len(batchCreated) != 3 {
		t.Fatalf("expected 3 expanded rules, got %d", len(batchCreated))
	}
	for i, expPort := range []int{20211, 20212, 20213} {
		if batchCreated[i].ListenPort != expPort {
			t.Fatalf("rule[%d] expected listen_port=%d, got %d", i, expPort, batchCreated[i].ListenPort)
		}
		wantTarget := fmt.Sprintf("1.1.1.1:%d", 30211+i)
		if !strings.Contains(batchCreated[i].TargetsJSON, wantTarget) {
			t.Fatalf("rule[%d] expected target %s in %s", i, wantTarget, batchCreated[i].TargetsJSON)
		}
	}

	// 4. NativeEngine runtime verification: active health check failover + IP ACL enforcement
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo target failed: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// Reserve and close a port so it acts as a dead target
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dead target failed: %v", err)
	}
	deadAddr := deadLn.Addr().String()
	_ = deadLn.Close()

	// Find a free listen port for NativeEngine
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen failed: %v", err)
	}
	listenPort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	pol := security.DefaultPolicy
	pol.AllowPrivateTargets = true
	eng := engine.NewNativeEngine(pol, nil)
	defer eng.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 4a. Apply rule with dead target #0 and healthy target #1, and ACL allow 127.0.0.0/8
	specAllow := protocol.RuleSpec{
		RuleID:      9001,
		Role:        protocol.RoleRelay,
		Engine:      protocol.EngineNative,
		Protocol:    "tcp",
		ListenHost:  "127.0.0.1",
		ListenPort:  listenPort,
		LoadBalance: "round_robin",
		Targets: []protocol.TargetEndpoint{
			{Address: deadAddr},
			{Address: echoLn.Addr().String()},
		},
		AccessMode:  "allow",
		AccessCIDRs: "127.0.0.0/8",
	}
	if err := eng.ApplyRule(ctx, specAllow); err != nil {
		t.Fatalf("ApplyRule allow failed: %v", err)
	}

	// Send 4 consecutive requests; all 4 should succeed because dead target is bypassed/marked unhealthy
	for i := 0; i < 4; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
		if err != nil {
			t.Fatalf("dial relay rule iter %d failed: %v", i, err)
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		msg := fmt.Sprintf("ping-%d", i)
		if _, err := conn.Write([]byte(msg)); err != nil {
			_ = conn.Close()
			t.Fatalf("write iter %d failed: %v", i, err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != msg {
			_ = conn.Close()
			t.Fatalf("read iter %d failed: got %q, err=%v", i, string(buf), err)
		}
		_ = conn.Close()
	}

	// 4b. Update rule with ACL deny 127.0.0.1/32 and verify connection is immediately closed
	specDeny := specAllow
	specDeny.AccessMode = "deny"
	specDeny.AccessCIDRs = "127.0.0.1/32"
	if err := eng.ApplyRule(ctx, specDeny); err != nil {
		t.Fatalf("ApplyRule deny failed: %v", err)
	}

	connDeny, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
	if err == nil {
		_ = connDeny.SetDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = connDeny.Write([]byte("blocked"))
		buf := make([]byte, 7)
		n, rErr := connDeny.Read(buf)
		_ = connDeny.Close()
		if n > 0 && rErr == nil {
			t.Fatalf("expected connection from denied IP 127.0.0.1 to be dropped, but received %d bytes", n)
		}
	}
}

func TestP2TOTP2FAAndAdminAPIKey(t *testing.T) {
	r, _, _ := setupTestServerWithDB(t)
	adminToken := loginAndGetToken(t, r, "admin@nexus.local", "admin123")

	// 1. Setup TOTP for admin user
	reqSetup := httptest.NewRequest(http.MethodPost, "/api/v1/user/totp/setup", nil)
	reqSetup.Header.Set("Authorization", "Bearer "+adminToken)
	wSetup := httptest.NewRecorder()
	r.ServeHTTP(wSetup, reqSetup)
	if wSetup.Code != http.StatusOK {
		t.Fatalf("expected 200 setting up TOTP, got %d: %s", wSetup.Code, wSetup.Body.String())
	}
	var setupResp struct {
		Secret     string `json:"secret"`
		OTPAuthURL string `json:"otpauth_url"`
	}
	if err := json.Unmarshal(wSetup.Body.Bytes(), &setupResp); err != nil {
		t.Fatalf("unmarshal TOTP setup failed: %v", err)
	}
	if setupResp.Secret == "" || !strings.HasPrefix(setupResp.OTPAuthURL, "otpauth://totp/") {
		t.Fatalf("unexpected setup response: %+v", setupResp)
	}

	// 2. Enable TOTP with wrong code should return 400
	badCodeBody, _ := json.Marshal(map[string]string{"code": "000000"})
	reqBadEnable := httptest.NewRequest(http.MethodPost, "/api/v1/user/totp/enable", bytes.NewReader(badCodeBody))
	reqBadEnable.Header.Set("Authorization", "Bearer "+adminToken)
	reqBadEnable.Header.Set("Content-Type", "application/json")
	wBadEnable := httptest.NewRecorder()
	r.ServeHTTP(wBadEnable, reqBadEnable)
	if wBadEnable.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 enabling TOTP with invalid code, got %d", wBadEnable.Code)
	}

	// 3. Enable TOTP with valid computed code from previous 30s window (-30s, accepted within ±1 step skew)
	now := time.Now()
	enableCode, err := ComputeTOTPCode(setupResp.Secret, now.Add(-30*time.Second))
	if err != nil {
		t.Fatalf("ComputeTOTPCode(enable) failed: %v", err)
	}
	goodCodeBody, _ := json.Marshal(map[string]string{"code": enableCode})
	reqEnable := httptest.NewRequest(http.MethodPost, "/api/v1/user/totp/enable", bytes.NewReader(goodCodeBody))
	reqEnable.Header.Set("Authorization", "Bearer "+adminToken)
	reqEnable.Header.Set("Content-Type", "application/json")
	wEnable := httptest.NewRecorder()
	r.ServeHTTP(wEnable, reqEnable)
	if wEnable.Code != http.StatusOK {
		t.Fatalf("expected 200 enabling TOTP, got %d: %s", wEnable.Code, wEnable.Body.String())
	}
	renewedTok := wEnable.Header().Get("X-Renewed-Token")
	if renewedTok == "" {
		t.Fatalf("expected X-Renewed-Token header on TOTP enablement")
	}
	// Pre-2FA JWT must now be rejected immediately (token_version incremented)
	reqStale := httptest.NewRequest(http.MethodGet, "/api/v1/user/profile", nil)
	reqStale.Header.Set("Authorization", "Bearer "+adminToken)
	wStale := httptest.NewRecorder()
	r.ServeHTTP(wStale, reqStale)
	if wStale.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 using pre-2FA token after enabling TOTP, got %d", wStale.Code)
	}
	adminToken = renewedTok

	// 4. Login without TOTP code should return 401 with totp_required=true
	loginNoCode, _ := json.Marshal(map[string]string{
		"email":    "admin@nexus.local",
		"password": "admin123",
	})
	reqLoginNoCode := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginNoCode))
	reqLoginNoCode.Header.Set("Content-Type", "application/json")
	reqLoginNoCode.RemoteAddr = nextIP()
	wLoginNoCode := httptest.NewRecorder()
	r.ServeHTTP(wLoginNoCode, reqLoginNoCode)
	if wLoginNoCode.Code != http.StatusUnauthorized || !strings.Contains(wLoginNoCode.Body.String(), "totp_required") {
		t.Fatalf("expected 401 totp_required, got %d: %s", wLoginNoCode.Code, wLoginNoCode.Body.String())
	}

	// 5. Login with current 30s window TOTP code should succeed once, and replaying the same code must return 401
	validCode, err := ComputeTOTPCode(setupResp.Secret, now)
	if err != nil {
		t.Fatalf("ComputeTOTPCode(login) failed: %v", err)
	}
	loginWithCode, _ := json.Marshal(map[string]string{
		"email":     "admin@nexus.local",
		"password":  "admin123",
		"totp_code": validCode,
	})
	reqLoginOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginWithCode))
	reqLoginOK.Header.Set("Content-Type", "application/json")
	reqLoginOK.RemoteAddr = nextIP()
	wLoginOK := httptest.NewRecorder()
	r.ServeHTTP(wLoginOK, reqLoginOK)
	if wLoginOK.Code != http.StatusOK {
		t.Fatalf("expected 200 login with TOTP code, got %d: %s", wLoginOK.Code, wLoginOK.Body.String())
	}

	reqReplay := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginWithCode))
	reqReplay.Header.Set("Content-Type", "application/json")
	reqReplay.RemoteAddr = nextIP()
	wReplay := httptest.NewRecorder()
	r.ServeHTTP(wReplay, reqReplay)
	if wReplay.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on TOTP same-step replay, got %d: %s", wReplay.Code, wReplay.Body.String())
	}

	// 6. Disable TOTP with current password and verify login without TOTP code works again
	disableBody, _ := json.Marshal(map[string]string{"password": "admin123"})
	reqDisable := httptest.NewRequest(http.MethodPost, "/api/v1/user/totp/disable", bytes.NewReader(disableBody))
	reqDisable.Header.Set("Authorization", "Bearer "+adminToken)
	reqDisable.Header.Set("Content-Type", "application/json")
	wDisable := httptest.NewRecorder()
	r.ServeHTTP(wDisable, reqDisable)
	if wDisable.Code != http.StatusOK {
		t.Fatalf("expected 200 disabling TOTP, got %d: %s", wDisable.Code, wDisable.Body.String())
	}

	reqLoginAfterDisable := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginNoCode))
	reqLoginAfterDisable.Header.Set("Content-Type", "application/json")
	reqLoginAfterDisable.RemoteAddr = nextIP()
	wLoginAfterDisable := httptest.NewRecorder()
	r.ServeHTTP(wLoginAfterDisable, reqLoginAfterDisable)
	if wLoginAfterDisable.Code != http.StatusOK {
		t.Fatalf("expected 200 login after disabling TOTP, got %d: %s", wLoginAfterDisable.Code, wLoginAfterDisable.Body.String())
	}

	// 7. Generate Admin API Key, authenticate with X-API-Key, then revoke and verify rejection
	reqGenKey := httptest.NewRequest(http.MethodPost, "/api/v1/admin/settings/api-key", nil)
	reqGenKey.Header.Set("Authorization", "Bearer "+adminToken)
	wGenKey := httptest.NewRecorder()
	r.ServeHTTP(wGenKey, reqGenKey)
	if wGenKey.Code != http.StatusOK {
		t.Fatalf("expected 200 generating API key, got %d: %s", wGenKey.Code, wGenKey.Body.String())
	}
	var keyResp struct {
		APIKey string `json:"api_key"`
		Prefix string `json:"admin_api_key_prefix"`
	}
	if err := json.Unmarshal(wGenKey.Body.Bytes(), &keyResp); err != nil {
		t.Fatalf("unmarshal API key response failed: %v", err)
	}
	if !strings.HasPrefix(keyResp.APIKey, "zp_live_") {
		t.Fatalf("expected zp_live_ prefix, got %q", keyResp.APIKey)
	}

	// Call admin endpoint using X-API-Key header
	reqViaKey := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	reqViaKey.Header.Set("X-API-Key", keyResp.APIKey)
	wViaKey := httptest.NewRecorder()
	r.ServeHTTP(wViaKey, reqViaKey)
	if wViaKey.Code != http.StatusOK {
		t.Fatalf("expected 200 authenticating via X-API-Key, got %d: %s", wViaKey.Code, wViaKey.Body.String())
	}

	// Revoke Admin API Key
	reqRevoke := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/settings/api-key", nil)
	reqRevoke.Header.Set("Authorization", "Bearer "+adminToken)
	wRevoke := httptest.NewRecorder()
	r.ServeHTTP(wRevoke, reqRevoke)
	if wRevoke.Code != http.StatusOK {
		t.Fatalf("expected 200 revoking API key, got %d: %s", wRevoke.Code, wRevoke.Body.String())
	}

	// Subsequent call with revoked X-API-Key should return 401
	reqAfterRevoke := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	reqAfterRevoke.Header.Set("X-API-Key", keyResp.APIKey)
	wAfterRevoke := httptest.NewRecorder()
	r.ServeHTTP(wAfterRevoke, reqAfterRevoke)
	if wAfterRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after API key revocation, got %d", wAfterRevoke.Code)
	}
}


