package api

import (
	"fmt"
	"net/http"
	"testing"

	"nexus-panel/internal/master/model"
	"nexus-panel/internal/master/service"
	"nexus-panel/pkg/protocol"
)

// Narrowing a tunnel's port range moves its rules into the new window; rules that no longer fit are disabled.
func TestLineRangeNarrowReallocatesRules(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	var node model.Node
	if err := db.First(&node).Error; err != nil {
		t.Fatal(err)
	}
	db.Model(&model.Node{}).Where("id = ?", node.ID).Update("port_range", "20000-30000")
	lineBody := map[string]any{"name": "narrow", "type": "direct", "ingress_node_id": node.ID, "engine": "native"}
	if w := doJSON(r, http.MethodPost, "/api/v1/admin/lines", admin, lineBody, ""); w.Code != http.StatusCreated {
		t.Fatalf("create line: %d %s", w.Code, w.Body.String())
	}
	var line model.TunnelLine
	db.Where("name = ?", "narrow").First(&line)

	for i, p := range []int{22000, 22001, 25000, 22002} {
		w := doJSON(r, http.MethodPost, "/api/v1/rules", admin, map[string]any{
			"name": fmt.Sprintf("r%d", i), "tunnel_line_id": line.ID, "protocol": "tcp", "listen_port": p,
			"targets": []map[string]string{{"address": "1.1.1.1:443"}},
		}, "")
		if w.Code != http.StatusCreated {
			t.Fatalf("create rule %d: %d %s", i, w.Code, w.Body.String())
		}
	}

	lineBody["port_range"] = "25000-25002"
	if w := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/lines/%d", line.ID), admin, lineBody, ""); w.Code != http.StatusOK {
		t.Fatalf("update line: %d %s", w.Code, w.Body.String())
	}
	var rules []model.ForwardRule
	db.Where("tunnel_line_id = ?", line.ID).Order("id").Find(&rules)
	if len(rules) != 4 {
		t.Fatalf("want 4 rules, got %d", len(rules))
	}
	if rules[2].ListenPort != 25000 || !rules[2].Enabled {
		t.Fatalf("in-range rule must keep its port, got %d enabled=%v", rules[2].ListenPort, rules[2].Enabled)
	}
	seen := map[int]bool{25000: true}
	moved, disabled := 0, 0
	for _, i := range []int{0, 1, 3} {
		rl := rules[i]
		if rl.Enabled {
			if rl.ListenPort < 25000 || rl.ListenPort > 25002 || seen[rl.ListenPort] {
				t.Fatalf("rule %d got bad port %d", rl.ID, rl.ListenPort)
			}
			seen[rl.ListenPort] = true
			moved++
		} else {
			if rl.Status != "error" {
				t.Fatalf("rule %d without free port must be in error state, got %q", rl.ID, rl.Status)
			}
			disabled++
		}
	}
	if moved != 2 || disabled != 1 {
		t.Fatalf("want 2 moved + 1 disabled, got %d + %d", moved, disabled)
	}
}

// Narrowing a node's port range moves rules (including admin direct rules) that fall outside it.
func TestNodeRangeNarrowReallocatesRules(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	var node model.Node
	if err := db.First(&node).Error; err != nil {
		t.Fatal(err)
	}
	db.Model(&model.Node{}).Where("id = ?", node.ID).Update("port_range", "20000-30000")
	for i, p := range []int{21000, 26500} {
		w := doJSON(r, http.MethodPost, "/api/v1/rules", admin, map[string]any{
			"name": fmt.Sprintf("d%d", i), "mode": "direct", "ingress_node_id": node.ID, "protocol": "tcp", "listen_port": p,
			"targets": []map[string]string{{"address": "1.1.1.1:443"}},
		}, "")
		if w.Code != http.StatusCreated {
			t.Fatalf("create rule %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	w := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", node.ID), admin, map[string]any{
		"name": node.Name, "port_range": "26000-27000",
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("update node: %d %s", w.Code, w.Body.String())
	}
	var d0, d1 model.ForwardRule
	db.Where("name = ?", "d0").First(&d0)
	db.Where("name = ?", "d1").First(&d1)
	if d1.ListenPort != 26500 {
		t.Fatalf("in-range rule must keep port 26500, got %d", d1.ListenPort)
	}
	if d0.ListenPort < 26000 || d0.ListenPort > 27000 || d0.ListenPort == 26500 || !d0.Enabled {
		t.Fatalf("out-of-range rule must move into 26000-27000, got %d enabled=%v", d0.ListenPort, d0.Enabled)
	}
}

func TestEffectiveEngine(t *testing.T) {
	user := &model.User{Role: "user", SpeedMbps: 100}
	unlimited := &model.User{Role: "user", SpeedMbps: 0}
	admin := &model.User{Role: "admin", SpeedMbps: 100}
	for i, tc := range []struct {
		eng   protocol.EngineType
		speed int
		owner *model.User
		want  protocol.EngineType
	}{
		{protocol.EngineGost, 0, user, protocol.EngineNative},        // inherits plan limit
		{protocol.EngineRealm, 20, unlimited, protocol.EngineNative}, // own limit
		{protocol.EngineRealm, 0, unlimited, protocol.EngineRealm},   // no limit at all
		{protocol.EngineGost, 50, admin, protocol.EngineGost},        // admin exempt
		{protocol.EngineNftables, 50, user, protocol.EngineNftables},
		{"", 0, user, protocol.EngineNative},
	} {
		got := service.EffectiveEngine(&model.ForwardRule{Engine: tc.eng, SpeedMbps: tc.speed}, tc.owner)
		if got != tc.want {
			t.Fatalf("case %d: got %s want %s", i, got, tc.want)
		}
	}
}

// Rules that cannot be moved are stopped; already-paused rules keep their status, and out-of-range rules cannot be
// re-enabled until they get an in-range port again.
func TestRangeNarrowPreservesPausedAndBlocksEnable(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	var node model.Node
	if err := db.First(&node).Error; err != nil {
		t.Fatal(err)
	}
	db.Model(&model.Node{}).Where("id = ?", node.ID).Update("port_range", "20000-30000")
	ids := map[string]uint64{}
	for name, p := range map[string]int{"p0": 21000, "p1": 21001, "p2": 26000} {
		w := doJSON(r, http.MethodPost, "/api/v1/rules", admin, map[string]any{
			"name": name, "mode": "direct", "ingress_node_id": node.ID, "protocol": "tcp", "listen_port": p,
			"targets": []map[string]string{{"address": "1.1.1.1:443"}},
		}, "")
		if w.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", name, w.Code, w.Body.String())
		}
		var rl model.ForwardRule
		db.Where("name = ?", name).First(&rl)
		ids[name] = rl.ID
	}
	toggle := func(name string) int {
		return doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/rules/%d/toggle", ids[name]), admin, nil, "").Code
	}
	if c := toggle("p1"); c != http.StatusOK {
		t.Fatalf("pause p1: %d", c)
	}
	get := func(name string) model.ForwardRule {
		var rl model.ForwardRule
		db.First(&rl, ids[name])
		return rl
	}
	putRange := func(rg string) {
		w := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", node.ID), admin, map[string]any{"name": node.Name, "port_range": rg}, "")
		if w.Code != http.StatusOK {
			t.Fatalf("update node range %s: %d %s", rg, w.Code, w.Body.String())
		}
	}
	putRange("26000-26000") // only p2's port fits, no free port for the others
	if p0 := get("p0"); p0.Enabled || p0.Status != "error" || p0.ListenPort != 21000 {
		t.Fatalf("p0 must be stopped with error, got enabled=%v status=%s port=%d", p0.Enabled, p0.Status, p0.ListenPort)
	}
	if p1 := get("p1"); p1.Enabled || p1.Status != "paused" || p1.LastError == "" {
		t.Fatalf("paused p1 must keep status paused with a last_error, got enabled=%v status=%s err=%q", p1.Enabled, p1.Status, p1.LastError)
	}
	if p2 := get("p2"); !p2.Enabled || p2.ListenPort != 26000 {
		t.Fatalf("p2 must be untouched, got enabled=%v port=%d", p2.Enabled, p2.ListenPort)
	}
	if c := toggle("p1"); c != http.StatusBadRequest {
		t.Fatalf("enabling an out-of-range rule must be refused, got %d", c)
	}
	putRange("26000-26010") // widening again re-homes the stranded rules
	for _, n := range []string{"p0", "p1"} {
		if rl := get(n); rl.ListenPort < 26001 || rl.ListenPort > 26010 {
			t.Fatalf("%s must be moved into 26001-26010, got %d", n, rl.ListenPort)
		}
	}
	if c := toggle("p1"); c != http.StatusOK || !get("p1").Enabled {
		t.Fatalf("p1 must be enable-able once in range, got %d", c)
	}
}

// A node-quota-paused rule stranded outside a narrowed range must not be auto-resumed outside the window.
func TestQuotaResumeSkipsOutOfRangeRule(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	var node model.Node
	if err := db.First(&node).Error; err != nil {
		t.Fatal(err)
	}
	db.Model(&model.Node{}).Where("id = ?", node.ID).Update("port_range", "20000-30000")
	for name, p := range map[string]int{"q0": 21000, "q1": 26000} {
		if w := doJSON(r, http.MethodPost, "/api/v1/rules", admin, map[string]any{
			"name": name, "mode": "direct", "ingress_node_id": node.ID, "protocol": "tcp", "listen_port": p,
			"targets": []map[string]string{{"address": "1.1.1.1:443"}},
		}, ""); w.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", name, w.Code, w.Body.String())
		}
	}
	db.Model(&model.ForwardRule{}).Where("ingress_node_id = ?", node.ID).Updates(map[string]any{"enabled": false, "status": "node_quota_exceeded"})
	// one edit: narrow the range so q0 cannot move (only q1's port fits) and lift the node quota -> resume runs
	w := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", node.ID), admin, map[string]any{
		"name": node.Name, "port_range": "26000-26000", "quota_bytes": 0,
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("update node: %d %s", w.Code, w.Body.String())
	}
	var q0, q1 model.ForwardRule
	db.Where("name = ?", "q0").First(&q0)
	db.Where("name = ?", "q1").First(&q1)
	if q0.Enabled || q0.Status != "error" {
		t.Fatalf("out-of-range q0 must not be resumed, got enabled=%v status=%s port=%d", q0.Enabled, q0.Status, q0.ListenPort)
	}
	if !q1.Enabled || (q1.Status != "running" && q1.Status != "syncing") { // syncing: node offline in tests
		t.Fatalf("in-range q1 must be resumed, got enabled=%v status=%s", q1.Enabled, q1.Status)
	}
}

// Relay ports: recorded with their egress node, unique per egress node in the DB, and moved when the egress node's
// range is narrowed.
func TestRelayPortTrackingAndRealloc(t *testing.T) {
	r, db, cleanup := setupTestServerWithDB(t)
	defer cleanup()
	admin := login(t, r, "admin@nexus.local", "admin123")
	var in model.Node
	if err := db.First(&in).Error; err != nil {
		t.Fatal(err)
	}
	w := doJSON(r, http.MethodPost, "/api/v1/admin/nodes", admin, map[string]any{
		"name": "egress", "server_ip": "203.0.113.9", "port_range": "40000-40100",
	}, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("create egress node: %d %s", w.Code, w.Body.String())
	}
	var eg model.Node
	db.Where("name = ?", "egress").First(&eg)
	if w := doJSON(r, http.MethodPost, "/api/v1/admin/lines", admin, map[string]any{
		"name": "enc", "type": "encrypt", "ingress_node_id": in.ID, "egress_node_id": eg.ID, "transport": "tls", "engine": "native",
	}, ""); w.Code != http.StatusCreated {
		t.Fatalf("create line: %d %s", w.Code, w.Body.String())
	}
	var line model.TunnelLine
	db.Where("name = ?", "enc").First(&line)
	for _, n := range []string{"t0", "t1"} {
		if w := doJSON(r, http.MethodPost, "/api/v1/rules", admin, map[string]any{
			"name": n, "tunnel_line_id": line.ID, "protocol": "tcp", "targets": []map[string]string{{"address": "1.1.1.1:443"}},
		}, ""); w.Code != http.StatusCreated {
			t.Fatalf("create rule %s: %d %s", n, w.Code, w.Body.String())
		}
	}
	get := func(n string) model.ForwardRule {
		var rl model.ForwardRule
		db.Where("name = ?", n).First(&rl)
		return rl
	}
	t0, t1 := get("t0"), get("t1")
	if t0.RelayPort < 40000 || t0.RelayPort > 40100 || t0.RelayNodeID != eg.ID || t1.RelayPort == t0.RelayPort {
		t.Fatalf("relay ports must be allocated on the egress node: t0=%d@%d t1=%d@%d", t0.RelayPort, t0.RelayNodeID, t1.RelayPort, t1.RelayNodeID)
	}
	// DB-level uniqueness of (relay node, relay port)
	if err := db.Model(&model.ForwardRule{}).Where("id = ?", t1.ID).Update("relay_port", t0.RelayPort).Error; err == nil {
		t.Fatal("duplicate (relay node, relay port) must be rejected by the database")
	}
	// narrow the egress node range -> relay ports move into it
	if w := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", eg.ID), admin, map[string]any{
		"name": "egress", "port_range": "40050-40060",
	}, ""); w.Code != http.StatusOK {
		t.Fatalf("narrow egress range: %d %s", w.Code, w.Body.String())
	}
	n0, n1 := get("t0"), get("t1")
	for _, rl := range []model.ForwardRule{n0, n1} {
		if rl.RelayPort < 40050 || rl.RelayPort > 40060 || !rl.Enabled {
			t.Fatalf("relay port of %s must move into 40050-40060, got %d enabled=%v", rl.Name, rl.RelayPort, rl.Enabled)
		}
	}
	if n0.RelayPort == n1.RelayPort {
		t.Fatalf("moved relay ports must stay distinct: %d", n0.RelayPort)
	}
	if n0.ListenPort != t0.ListenPort {
		t.Fatalf("ingress listen port must not change: %d -> %d", t0.ListenPort, n0.ListenPort)
	}
	// editing a rule keeps DB-owned fields (relay port, paused state) instead of a stale snapshot
	db.Model(&model.ForwardRule{}).Where("id = ?", n1.ID).Updates(map[string]any{"enabled": false, "status": "paused"})
	if w := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/rules/%d", n1.ID), admin, map[string]any{
		"name": "t1-renamed", "tunnel_line_id": line.ID, "protocol": "tcp", "listen_port": n1.ListenPort,
		"targets": []map[string]string{{"address": "1.1.1.2:443"}},
	}, ""); w.Code != http.StatusOK {
		t.Fatalf("edit rule: %d %s", w.Code, w.Body.String())
	}
	var e1 model.ForwardRule
	db.First(&e1, n1.ID)
	if e1.Name != "t1-renamed" || e1.RelayPort != n1.RelayPort || e1.RelayNodeID != eg.ID || e1.Enabled || e1.Status != "paused" {
		t.Fatalf("edit must keep relay/paused state: %+v", e1)
	}
	db.Model(&model.ForwardRule{}).Where("id = ?", n1.ID).Updates(map[string]any{"enabled": true, "status": "running", "name": "t1"})

	// no room at all -> rule stopped and its relay port released
	if w := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", eg.ID), admin, map[string]any{
		"name": "egress", "port_range": "40099-40099",
	}, ""); w.Code != http.StatusOK {
		t.Fatalf("narrow egress range: %d %s", w.Code, w.Body.String())
	}
	n0, n1 = get("t0"), get("t1")
	okCount, stopped := 0, 0
	for _, rl := range []model.ForwardRule{n0, n1} {
		switch {
		case rl.Enabled && rl.RelayPort == 40099:
			okCount++
		case !rl.Enabled && rl.Status == "error" && rl.RelayPort == 0:
			stopped++
		default:
			t.Fatalf("unexpected state for %s: enabled=%v status=%s relay=%d", rl.Name, rl.Enabled, rl.Status, rl.RelayPort)
		}
	}
	if okCount != 1 || stopped != 1 {
		t.Fatalf("want 1 moved + 1 stopped, got %d + %d", okCount, stopped)
	}
}

// Batch picking hands out distinct, policy-valid ports.
func TestPickFreePort(t *testing.T) {
	occ := map[int]bool{20000: true}
	a, err := service.PickFreePort(20000, 20002, occ)
	if err != nil || a != 20001 {
		t.Fatalf("got %d %v", a, err)
	}
	b, _ := service.PickFreePort(20000, 20002, occ)
	if b != 20002 {
		t.Fatalf("second pick must be 20002, got %d", b)
	}
	if _, err := service.PickFreePort(20000, 20002, occ); err == nil {
		t.Fatal("exhausted range must error")
	}
}
