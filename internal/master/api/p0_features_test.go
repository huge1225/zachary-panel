package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"nexus-panel/internal/master/hub"
	"nexus-panel/internal/master/model"
	"nexus-panel/internal/master/service"
)

func TestP0RedeemCodeManagementAndBalancePlanRedemption(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	// Non-admin cannot list or generate redeem codes
	if w := doJSON(r, http.MethodGet, "/api/v1/admin/redeem", userTok, nil, ""); w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin list redeem, got %d", w.Code)
	}

	// 1. Admin generates a balance top-up redeem code (50.00 RMB = 5000 cents, 0 duration so expire_at shouldn't change)
	wBal := doJSON(r, http.MethodPost, "/api/v1/admin/redeem/generate", adminTok, map[string]any{
		"count":         2,
		"balance_cents": 5000,
		"prefix":        "BAL",
		"note":          "Balance batch",
	}, "")
	if wBal.Code != http.StatusCreated {
		t.Fatalf("generate balance code failed: %d %s", wBal.Code, wBal.Body.String())
	}
	var balCodes []model.RedeemCode
	_ = json.Unmarshal(wBal.Body.Bytes(), &balCodes)
	if len(balCodes) != 2 || balCodes[0].BalanceCents != 5000 || balCodes[0].Duration != 0 {
		t.Fatalf("unexpected balance codes: %+v", balCodes)
	}

	var uBefore model.User
	db.Where("email = ?", "user@nexus.local").First(&uBefore)

	// User redeems the first balance code
	wRedeemBal := doJSON(r, http.MethodPost, "/api/v1/redeem", userTok, map[string]any{
		"code": balCodes[0].Code,
	}, "")
	if wRedeemBal.Code != http.StatusOK {
		t.Fatalf("redeem balance code failed: %d %s", wRedeemBal.Code, wRedeemBal.Body.String())
	}
	var uAfter model.User
	db.Where("email = ?", "user@nexus.local").First(&uAfter)
	if uAfter.BalanceCents != uBefore.BalanceCents+5000 {
		t.Fatalf("expected balance +%d, got before=%d after=%d", 5000, uBefore.BalanceCents, uAfter.BalanceCents)
	}

	// Re-redeeming same code must return 409 Conflict
	if w := doJSON(r, http.MethodPost, "/api/v1/redeem", userTok, map[string]any{"code": balCodes[0].Code}, ""); w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for already used code, got %d", w.Code)
	}

	// 2. Admin generates a plan-bound redeem code (Plan #2 = VIP)
	wPlan := doJSON(r, http.MethodPost, "/api/v1/admin/redeem/generate", adminTok, map[string]any{
		"count":   1,
		"plan_id": 2,
		"prefix":  "VIP",
		"note":    "VIP plan card",
	}, "")
	if wPlan.Code != http.StatusCreated {
		t.Fatalf("generate plan code failed: %d %s", wPlan.Code, wPlan.Body.String())
	}
	var planCodes []model.RedeemCode
	_ = json.Unmarshal(wPlan.Body.Bytes(), &planCodes)
	if len(planCodes) != 1 || planCodes[0].PlanID != 2 || planCodes[0].QuotaBytes <= 0 {
		t.Fatalf("unexpected plan code: %+v", planCodes)
	}

	wRedeemPlan := doJSON(r, http.MethodPost, "/api/v1/redeem", userTok, map[string]any{
		"code": planCodes[0].Code,
	}, "")
	if wRedeemPlan.Code != http.StatusOK {
		t.Fatalf("redeem plan code failed: %d %s", wRedeemPlan.Code, wRedeemPlan.Body.String())
	}
	db.Where("email = ?", "user@nexus.local").First(&uAfter)
	if uAfter.PlanID != 2 {
		t.Fatalf("expected user plan_id=2 after redeeming VIP code, got %d", uAfter.PlanID)
	}

	// 3. Admin lists redeem codes with filters (`used` / `unused`) and deletes
	wListUsed := doJSON(r, http.MethodGet, "/api/v1/admin/redeem?status=used", adminTok, nil, "")
	if wListUsed.Code != http.StatusOK {
		t.Fatalf("list used redeem codes failed: %d", wListUsed.Code)
	}
	var listedUsed []model.RedeemCode
	_ = json.Unmarshal(wListUsed.Body.Bytes(), &listedUsed)
	if len(listedUsed) != 2 || listedUsed[0].UsedByEmail != "user@nexus.local" {
		t.Fatalf("expected 2 used codes with enriched email, got %+v", listedUsed)
	}

	// Single delete unused code
	wDel := doJSON(r, http.MethodDelete, fmt.Sprintf("/api/v1/admin/redeem/%d", balCodes[1].ID), adminTok, nil, "")
	if wDel.Code != http.StatusOK {
		t.Fatalf("delete single redeem code failed: %d %s", wDel.Code, wDel.Body.String())
	}

	// Batch delete used codes
	wBatchDel := doJSON(r, http.MethodPost, "/api/v1/admin/redeem/batch-delete", adminTok, map[string]any{
		"mode": "used",
	}, "")
	if wBatchDel.Code != http.StatusOK {
		t.Fatalf("batch delete used redeem codes failed: %d %s", wBatchDel.Code, wBatchDel.Body.String())
	}
	var remaining int64
	db.Model(&model.RedeemCode{}).Count(&remaining)
	if remaining != 0 {
		t.Fatalf("expected 0 remaining redeem codes, got %d", remaining)
	}
}

func TestP0Dashboard24hSeriesAndTopRankings(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	var u model.User
	db.Where("email = ?", "user@nexus.local").First(&u)

	// Insert two hourly stat rows in the current hour bucket for different rules and one stale row >30 days old
	curBucket := db.NowFunc().Truncate(3600_000_000_000).Format("2006-01-02 15:00")
	db.Create(&model.TrafficHourlyStat{
		UserID:      u.ID,
		RuleID:      1,
		NodeID:      1,
		HourBucket:  curBucket,
		UploadBytes: 1000,
		DownBytes:   2000,
		BilledBytes: 3000,
	})
	db.Create(&model.TrafficHourlyStat{
		UserID:      u.ID,
		RuleID:      2,
		NodeID:      1,
		HourBucket:  curBucket,
		UploadBytes: 500,
		DownBytes:   1500,
		BilledBytes: 2000,
	})
	db.Create(&model.TrafficHourlyStat{
		UserID:      u.ID,
		RuleID:      1,
		NodeID:      1,
		HourBucket:  "2020-01-01 00:00",
		UploadBytes: 9999,
		DownBytes:   9999,
		BilledBytes: 9999,
	})

	// User dashboard returns 24 buckets, aggregating curBucket to 5000 billed_bytes, without top_users/global_hourly_stats
	wUserDash := doJSON(r, http.MethodGet, "/api/v1/dashboard", userTok, nil, "")
	if wUserDash.Code != http.StatusOK {
		t.Fatalf("user dashboard failed: %d", wUserDash.Code)
	}
	var uDash struct {
		HourlyStats []struct {
			HourBucket  string `json:"hour_bucket"`
			BilledBytes int64  `json:"billed_bytes"`
		} `json:"hourly_stats"`
		GlobalHourlyStats []any `json:"global_hourly_stats"`
		TopUsers          []any `json:"top_users"`
	}
	_ = json.Unmarshal(wUserDash.Body.Bytes(), &uDash)
	if len(uDash.HourlyStats) != 24 || uDash.HourlyStats[23].BilledBytes != 5000 {
		t.Fatalf("expected 24 hourly buckets with last bucket=5000, got len=%d last=%+v", len(uDash.HourlyStats), uDash.HourlyStats[len(uDash.HourlyStats)-1])
	}
	if len(uDash.GlobalHourlyStats) != 0 || len(uDash.TopUsers) != 0 {
		t.Fatalf("expected non-admin dashboard to omit global stats/top_users")
	}

	// Admin dashboard includes global_hourly_stats, top_users, and top_nodes
	wAdminDash := doJSON(r, http.MethodGet, "/api/v1/dashboard", adminTok, nil, "")
	if wAdminDash.Code != http.StatusOK {
		t.Fatalf("admin dashboard failed: %d", wAdminDash.Code)
	}
	var aDash struct {
		GlobalHourlyStats []struct {
			HourBucket  string `json:"hour_bucket"`
			BilledBytes int64  `json:"billed_bytes"`
		} `json:"global_hourly_stats"`
		TopUsers []any `json:"top_users"`
		TopNodes []any `json:"top_nodes"`
	}
	_ = json.Unmarshal(wAdminDash.Body.Bytes(), &aDash)
	if len(aDash.GlobalHourlyStats) != 24 || aDash.GlobalHourlyStats[23].BilledBytes != 5000 || len(aDash.TopUsers) == 0 || len(aDash.TopNodes) == 0 {
		t.Fatalf("unexpected admin dashboard payload: global_len=%d top_users=%d top_nodes=%d", len(aDash.GlobalHourlyStats), len(aDash.TopUsers), len(aDash.TopNodes))
	}
}

func TestP0RuleAndUserSearchFiltering(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	var u model.User
	db.Where("email = ?", "user@nexus.local").First(&u)
	db.Create(&model.ForwardRule{
		UserID:        1,
		Name:          "AdminRule-HK",
		TunnelLineID:  1,
		IngressNodeID: 1,
		Protocol:      "tcp",
		ListenPort:    20001,
		TargetsJSON:   `[{"address":"1.1.1.1:443"}]`,
		Enabled:       true,
		Status:        "running",
	})
	db.Create(&model.ForwardRule{
		UserID:        u.ID,
		Name:          "UserRule-SG",
		TunnelLineID:  1,
		IngressNodeID: 1,
		Protocol:      "udp",
		ListenPort:    20002,
		TargetsJSON:   `[{"address":"8.8.8.8:53"}]`,
		Enabled:       true,
		Status:        "running",
	})

	// Filter rules by q=20001
	wRules := doJSON(r, http.MethodGet, "/api/v1/rules?all=1&q=20001", adminTok, nil, "")
	if wRules.Code != http.StatusOK {
		t.Fatalf("filter rules failed: %d", wRules.Code)
	}
	var filteredRules []model.ForwardRule
	_ = json.Unmarshal(wRules.Body.Bytes(), &filteredRules)
	if len(filteredRules) != 1 || filteredRules[0].ListenPort != 20001 {
		t.Fatalf("expected 1 rule on port 20001, got %+v", filteredRules)
	}

	// Non-admin user q filter still scoped to their own rules
	wUserRules := doJSON(r, http.MethodGet, "/api/v1/rules?all=1&q=20002", userTok, nil, "")
	_ = json.Unmarshal(wUserRules.Body.Bytes(), &filteredRules)
	if len(filteredRules) != 1 || filteredRules[0].ListenPort != 20002 {
		t.Fatalf("expected 1 rule on port 20002 for user, got %+v", filteredRules)
	}

	// Admin filter users by q=user@nexus.local and status=active
	wUsers := doJSON(r, http.MethodGet, "/api/v1/admin/users?q=user@nexus.local&status=active", adminTok, nil, "")
	if wUsers.Code != http.StatusOK {
		t.Fatalf("filter users failed: %d", wUsers.Code)
	}
	var filteredUsers []model.User
	_ = json.Unmarshal(wUsers.Body.Bytes(), &filteredUsers)
	if len(filteredUsers) != 1 || filteredUsers[0].Email != "user@nexus.local" {
		t.Fatalf("expected 1 active user matching email, got %+v", filteredUsers)
	}
}

func TestP0PeriodicNodeAndUserTrafficReset(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")

	// 1. Set node #1 reset_day = 1, used_bytes = 500 GB, and create a node_quota_exceeded rule
	wNodeUpd := doJSON(r, http.MethodPut, "/api/v1/admin/nodes/1", adminTok, map[string]any{
		"reset_day":  1,
		"used_bytes": 500 * 1024 * 1024 * 1024,
	}, "")
	if wNodeUpd.Code != http.StatusOK {
		t.Fatalf("update node reset_day failed: %d %s", wNodeUpd.Code, wNodeUpd.Body.String())
	}

	var u model.User
	db.Where("email = ?", "user@nexus.local").First(&u)
	oldReset := time.Now().UTC().AddDate(0, 0, -31)
	db.Model(&model.User{}).Where("id = ?", u.ID).Updates(map[string]any{
		"monthly_reset": true,
		"used_bytes":    u.QuotaBytes,
		"last_reset_at": &oldReset,
	})

	ruleNodePaused := model.ForwardRule{
		UserID:        1,
		Name:          "NodePausedRule",
		TunnelLineID:  1,
		IngressNodeID: 1,
		Protocol:      "tcp",
		ListenPort:    20101,
		TargetsJSON:   `[{"address":"1.1.1.1:443"}]`,
		Enabled:       false,
		Status:        "node_quota_exceeded",
	}
	db.Create(&ruleNodePaused)

	ruleUserPaused := model.ForwardRule{
		UserID:        u.ID,
		Name:          "UserPausedRule",
		TunnelLineID:  1,
		IngressNodeID: 1,
		Protocol:      "tcp",
		ListenPort:    20102,
		TargetsJSON:   `[{"address":"8.8.8.8:53"}]`,
		Enabled:       false,
		Status:        "quota_exceeded",
	}
	db.Create(&ruleUserPaused)

	// 2. Run ProcessPeriodicResets and verify both node #1 and user traffic reset to 0 and both rules resume
	orch := service.NewOrchestrator(db, hub.NewAgentHub(db))
	orch.ProcessPeriodicResets(time.Now().UTC())

	var n1 model.Node
	db.First(&n1, 1)
	if n1.UsedBytes != 0 || n1.LastResetMonth == "" {
		t.Fatalf("expected node #1 used_bytes=0 after periodic reset, got used=%d month=%s", n1.UsedBytes, n1.LastResetMonth)
	}
	var refreshedNodeRule model.ForwardRule
	db.First(&refreshedNodeRule, ruleNodePaused.ID)
	if !refreshedNodeRule.Enabled || (refreshedNodeRule.Status != "running" && refreshedNodeRule.Status != "syncing") {
		t.Fatalf("expected node_quota_exceeded rule to resume, got enabled=%v status=%s", refreshedNodeRule.Enabled, refreshedNodeRule.Status)
	}

	var refreshedUser model.User
	db.First(&refreshedUser, u.ID)
	if refreshedUser.UsedBytes != 0 {
		t.Fatalf("expected user used_bytes=0 after 30-day periodic reset, got %d", refreshedUser.UsedBytes)
	}
	var refreshedUserRule model.ForwardRule
	db.First(&refreshedUserRule, ruleUserPaused.ID)
	if !refreshedUserRule.Enabled || (refreshedUserRule.Status != "running" && refreshedUserRule.Status != "syncing") {
		t.Fatalf("expected user quota_exceeded rule to resume, got enabled=%v status=%s", refreshedUserRule.Enabled, refreshedUserRule.Status)
	}

	// 3. Also verify manual POST /api/v1/admin/nodes/1/reset-traffic endpoint
	db.Model(&model.Node{}).Where("id = ?", 1).Update("used_bytes", 123456)
	wResetNode := doJSON(r, http.MethodPost, "/api/v1/admin/nodes/1/reset-traffic", adminTok, nil, "")
	if wResetNode.Code != http.StatusOK {
		t.Fatalf("manual node reset-traffic failed: %d %s", wResetNode.Code, wResetNode.Body.String())
	}
	db.First(&n1, 1)
	if n1.UsedBytes != 0 {
		t.Fatalf("expected node #1 used_bytes=0 after manual reset, got %d", n1.UsedBytes)
	}
}


