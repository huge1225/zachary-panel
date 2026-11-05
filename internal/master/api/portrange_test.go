package api

import (
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	"nexus-panel/internal/master/hub"
	"nexus-panel/internal/master/model"
	"nexus-panel/internal/master/service"
	"nexus-panel/pkg/protocol"
)

// Tunnel-level port ranges: validated against the ingress node range, and rule ports are allocated inside them.
func TestTunnelPortRange(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	var node model.Node
	if err := db.First(&node).Error; err != nil {
		t.Fatal(err)
	}
	db.Model(&model.Node{}).Where("id = ?", node.ID).Update("port_range", "20000-30000")

	// outside the node range -> rejected
	w := doJSON(r, http.MethodPost, "/api/v1/admin/lines", admin, map[string]any{
		"name": "bad-range", "type": "direct", "ingress_node_id": node.ID, "engine": "native", "port_range": "40000-40010",
	}, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("line range outside node range must be rejected, got %d %s", w.Code, w.Body.String())
	}
	// malformed -> rejected
	w = doJSON(r, http.MethodPost, "/api/v1/admin/lines", admin, map[string]any{
		"name": "bad-format", "type": "direct", "ingress_node_id": node.ID, "engine": "native", "port_range": "abc",
	}, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed line range must be rejected, got %d", w.Code)
	}

	w = doJSON(r, http.MethodPost, "/api/v1/admin/lines", admin, map[string]any{
		"name": "ranged", "type": "direct", "ingress_node_id": node.ID, "engine": "native", "port_range": " 25000 - 25001 ",
	}, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("create ranged line: %d %s", w.Code, w.Body.String())
	}
	var line model.TunnelLine
	db.Where("name = ?", "ranged").First(&line)
	if line.PortRange != "25000-25001" {
		t.Fatalf("port range not normalized: %q", line.PortRange)
	}

	create := func(name string, port int) (int, int) {
		w := doJSON(r, http.MethodPost, "/api/v1/rules", admin, map[string]any{
			"name": name, "tunnel_line_id": line.ID, "protocol": "tcp", "listen_port": port,
			"targets": []map[string]string{{"address": "1.1.1.1:443"}},
		}, "")
		var rule model.ForwardRule
		db.Where("name = ?", name).First(&rule)
		return w.Code, rule.ListenPort
	}
	if code, p := create("a", 0); code != http.StatusCreated || p != 25000 {
		t.Fatalf("auto port should be 25000, got code=%d port=%d", code, p)
	}
	if code, _ := create("out", 26000); code != http.StatusBadRequest {
		t.Fatalf("requested port outside tunnel range must be rejected, got %d", code)
	}
	if code, p := create("b", 0); code != http.StatusCreated || p != 25001 {
		t.Fatalf("second auto port should be 25001, got code=%d port=%d", code, p)
	}
	if code, _ := create("c", 0); code != http.StatusBadRequest {
		t.Fatalf("exhausted tunnel range must be rejected, got %d", code)
	}
}

// Database-level uniqueness of (ingress node, listen port) for multi-master safety; port 0 is exempt.
func TestRulePortUniqueIndex(t *testing.T) {
	_, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	var node model.Node
	if err := db.First(&node).Error; err != nil {
		t.Fatal(err)
	}
	mk := func(name string, port int) error {
		return db.Create(&model.ForwardRule{UserID: 1, Name: name, Mode: "direct", IngressNodeID: node.ID, Engine: "native",
			Protocol: "tcp", TargetsJSON: `[{"address":"1.1.1.1:443"}]`, ListenPort: port, Enabled: true, Status: "running"}).Error
	}
	if err := mk("u1", 45678); err != nil {
		t.Fatal(err)
	}
	if err := mk("u2", 45678); err == nil {
		t.Fatal("duplicate (node, port) must be rejected by the database")
	}
	if err := mk("z1", 0); err != nil {
		t.Fatal(err)
	}
	if err := mk("z2", 0); err != nil {
		t.Fatalf("transient port 0 must not collide: %v", err)
	}
}

// gost / realm cannot enforce bandwidth limits: speed-limited rules of normal users are compiled onto native.
func TestSpeedLimitedRuleFallsBackToNative(t *testing.T) {
	t.Setenv("NEXUS_SEED_DEMO", "true")
	t.Setenv("NEXUS_ADMIN_PASSWORD", "admin123")
	t.Setenv("NEXUS_DEMO_USER_PASSWORD", "user12345")
	db, err := model.InitDB("sqlite", filepath.Join(t.TempDir(), "o.db"))
	if err != nil {
		t.Fatal(err)
	}
	orch := service.NewOrchestrator(db, hub.NewAgentHub(db))
	uid := userIDByEmail(t, db, "user@nexus.local")
	adminID := userIDByEmail(t, db, "admin@nexus.local")
	var node model.Node
	db.First(&node)
	for i, tc := range []struct {
		owner uint64
		eng   protocol.EngineType
		speed int
		want  protocol.EngineType
	}{
		{uid, protocol.EngineGost, 50, protocol.EngineNative},
		{uid, protocol.EngineRealm, 50, protocol.EngineNative},
		{uid, protocol.EngineNftables, 50, protocol.EngineNftables},
		{adminID, protocol.EngineRealm, 50, protocol.EngineRealm},
	} {
		rule := model.ForwardRule{ID: uint64(9000 + i), UserID: tc.owner, Name: fmt.Sprintf("s%d", i), Mode: "direct",
			IngressNodeID: node.ID, Engine: tc.eng, Protocol: "tcp", TargetsJSON: `[{"address":"1.1.1.1:443"}]`,
			ListenPort: 46000 + i, SpeedMbps: tc.speed}
		spec, _, _, err := orch.CompileRuleSpecs(&rule)
		if err != nil {
			t.Fatal(err)
		}
		if spec.Engine != tc.want {
			t.Fatalf("case %d: engine %s, want %s", i, spec.Engine, tc.want)
		}
	}
}

// Narrowing a node's port range must not orphan a tunnel's port range.
func TestNodeRangeChangeKeepsTunnelRangesInside(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	var node model.Node
	if err := db.First(&node).Error; err != nil {
		t.Fatal(err)
	}
	db.Model(&model.Node{}).Where("id = ?", node.ID).Update("port_range", "20000-30000")
	if w := doJSON(r, http.MethodPost, "/api/v1/admin/lines", admin, map[string]any{
		"name": "ranged", "type": "direct", "ingress_node_id": node.ID, "engine": "native", "port_range": "29000-29999",
	}, ""); w.Code != http.StatusCreated {
		t.Fatalf("create line: %d %s", w.Code, w.Body.String())
	}
	w := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", node.ID), admin, map[string]any{
		"name": node.Name, "port_range": "20000-25000",
	}, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("node range excluding a tunnel range must be rejected, got %d %s", w.Code, w.Body.String())
	}
	w = doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", node.ID), admin, map[string]any{
		"name": node.Name, "port_range": "21000-29999",
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("compatible node range must be accepted, got %d %s", w.Code, w.Body.String())
	}
}
