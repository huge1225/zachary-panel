package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"nexus-panel/internal/master/hub"
	"nexus-panel/internal/master/model"
	"nexus-panel/internal/master/service"
	"nexus-panel/pkg/protocol"
)

func TestPhase2CompositeIndexesPaginationAndBatchStats(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()

	// 1. Verify composite & high-frequency indexes exist on Migrator
	indexChecks := []struct {
		dst  any
		name string
	}{
		{&model.User{}, "idx_user_status_expire"},
		{&model.ForwardRule{}, "idx_rule_user_enabled"},
		{&model.BillingOrder{}, "idx_order_status_created"},
		{&model.BillingOrder{}, "idx_order_user_status"},
		{&model.TrafficHourlyStat{}, "idx_stat_user_rule_hour"},
		{&model.AuditLog{}, "idx_audit_action_created"},
	}
	for _, ic := range indexChecks {
		if !db.Migrator().HasIndex(ic.dst, ic.name) {
			t.Fatalf("expected index %q on %T to exist", ic.name, ic.dst)
		}
	}

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	// Seed 5 rules for user so we can test pagination + batch traffic aggregation
	var createdRuleIDs []uint64
	for i := 1; i <= 5; i++ {
		w := doJSON(r, http.MethodPost, "/api/v1/rules", userTok, map[string]any{
			"name":            fmt.Sprintf("perf-rule-%d", i),
			"mode":            "direct",
			"ingress_node_id": 1,
			"tunnel_line_id":  1,
			"engine":          "native",
			"protocol":        "tcp",
			"listen_port":     0,
			"load_balance":    "round_robin",
			"targets":         []map[string]any{{"address": fmt.Sprintf("1.1.1.%d:443", i)}},
		}, "")
		if w.Code != http.StatusCreated {
			t.Fatalf("create rule %d failed: %d %s", i, w.Code, w.Body.String())
		}
		var fr model.ForwardRule
		_ = json.Unmarshal(w.Body.Bytes(), &fr)
		createdRuleIDs = append(createdRuleIDs, fr.ID)
	}

	// 2. Test /api/v1/rules default bare array + X-Total-Count header AND paged=1 envelope
	wBare := doJSON(r, http.MethodGet, "/api/v1/rules?page=1&page_size=2", userTok, nil, "")
	if wBare.Code != http.StatusOK {
		t.Fatalf("list rules bare failed: %d", wBare.Code)
	}
	if wBare.Header().Get("X-Page") != "1" || wBare.Header().Get("X-Page-Size") != "2" {
		t.Fatalf("expected X-Page=1 and X-Page-Size=2 headers, got %q / %q", wBare.Header().Get("X-Page"), wBare.Header().Get("X-Page-Size"))
	}
	var bareSlice []model.ForwardRule
	if err := json.Unmarshal(wBare.Body.Bytes(), &bareSlice); err != nil {
		t.Fatalf("expected bare array JSON, got err=%v body=%s", err, wBare.Body.String())
	}
	if len(bareSlice) != 2 {
		t.Fatalf("expected 2 rules on page 1, got %d", len(bareSlice))
	}

	wPaged := doJSON(r, http.MethodGet, "/api/v1/rules?all=1&page=2&page_size=2&paged=1", adminTok, nil, "")
	if wPaged.Code != http.StatusOK {
		t.Fatalf("list rules paged failed: %d", wPaged.Code)
	}
	var pagedEnv struct {
		Items    []model.ForwardRule `json:"items"`
		Total    int64               `json:"total"`
		Page     int                 `json:"page"`
		PageSize int                 `json:"page_size"`
	}
	if err := json.Unmarshal(wPaged.Body.Bytes(), &pagedEnv); err != nil {
		t.Fatalf("expected paged envelope JSON, got err=%v", err)
	}
	if pagedEnv.Total < 5 || pagedEnv.Page != 2 || pagedEnv.PageSize != 2 || len(pagedEnv.Items) != 2 {
		t.Fatalf("unexpected paged envelope: %+v", pagedEnv)
	}

	// 3. Test pagination envelope across admin users, orders, redeem codes, and audit logs
	wGen := doJSON(r, http.MethodPost, "/api/v1/admin/redeem/generate", adminTok, map[string]any{
		"count":         4,
		"balance_cents": 500,
		"prefix":        "PF",
	}, "")
	var genCodes []model.RedeemCode
	_ = json.Unmarshal(wGen.Body.Bytes(), &genCodes)
	if len(genCodes) > 0 {
		doJSON(r, http.MethodPost, "/api/v1/redeem", userTok, map[string]any{"code": genCodes[0].Code}, "")
	}
	for _, ep := range []string{
		"/api/v1/admin/users?page=1&page_size=1&paged=1",
		"/api/v1/orders?all=1&page=1&page_size=2&paged=1",
		"/api/v1/admin/redeem?page=1&page_size=2&paged=1",
		"/api/v1/admin/audit-logs?page=1&page_size=2&paged=1",
	} {
		w := doJSON(r, http.MethodGet, ep, adminTok, nil, "")
		if w.Code != http.StatusOK {
			t.Fatalf("endpoint %s failed: %d %s", ep, w.Code, w.Body.String())
		}
		var env struct {
			Items    json.RawMessage `json:"items"`
			Total    int64           `json:"total"`
			Page     int             `json:"page"`
			PageSize int             `json:"page_size"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
			t.Fatalf("endpoint %s invalid envelope: %v", ep, err)
		}
		if env.Page != 1 || env.Total < 1 {
			t.Fatalf("endpoint %s unexpected meta: total=%d page=%d", ep, env.Total, env.Page)
		}
	}

	// 4. Test batch HandleTrafficReport + SQL GROUP BY dashboard stats
	agentHub := hub.NewAgentHub(db)
	orch := service.NewOrchestrator(db, agentHub)
	var deltas []protocol.RuleTrafficDelta
	for _, rid := range createdRuleIDs {
		deltas = append(deltas, protocol.RuleTrafficDelta{
			RuleID:      rid,
			Role:        protocol.RoleRelay,
			UploadBytes: 1024,
			DownBytes:   2048,
		})
	}
	// Report twice in the same hour bucket to verify upsert + GROUP BY SUM across multiple rules
	orch.HandleTrafficReport(1, protocol.TrafficReportPayload{Deltas: deltas})
	orch.HandleTrafficReport(1, protocol.TrafficReportPayload{Deltas: deltas})

	wDash := doJSON(r, http.MethodGet, "/api/v1/dashboard", adminTok, nil, "")
	if wDash.Code != http.StatusOK {
		t.Fatalf("dashboard failed: %d %s", wDash.Code, wDash.Body.String())
	}
	var dash struct {
		GlobalHourlyStats []struct {
			HourBucket  string `json:"hour_bucket"`
			UploadBytes int64  `json:"upload_bytes"`
			DownBytes   int64  `json:"down_bytes"`
			BilledBytes int64  `json:"billed_bytes"`
		} `json:"global_hourly_stats"`
	}
	if err := json.Unmarshal(wDash.Body.Bytes(), &dash); err != nil {
		t.Fatalf("unmarshal dashboard failed: %v", err)
	}
	var sumUp, sumDown int64
	for _, pt := range dash.GlobalHourlyStats {
		sumUp += pt.UploadBytes
		sumDown += pt.DownBytes
	}
	expectedUp := int64(len(createdRuleIDs)) * 1024 * 2
	expectedDown := int64(len(createdRuleIDs)) * 2048 * 2
	if sumUp < expectedUp || sumDown < expectedDown {
		t.Fatalf("expected global hourly sum >= (%d, %d), got (%d, %d)", expectedUp, expectedDown, sumUp, sumDown)
	}
}
