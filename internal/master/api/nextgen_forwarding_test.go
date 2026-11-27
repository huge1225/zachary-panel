package api

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"nexus-panel/internal/agent/engine"
	"nexus-panel/internal/agent/security"
	"nexus-panel/internal/master/hub"
	"nexus-panel/internal/master/model"
	"nexus-panel/internal/master/service"
	"nexus-panel/pkg/protocol"
)

func setupNextGenEnv(t *testing.T) (*gin.Engine, *gorm.DB, *service.Orchestrator, *hub.AgentHub, *Server, func()) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	t.Setenv("NEXUS_SEED_DEMO", "true")
	t.Setenv("NEXUS_ADMIN_PASSWORD", "admin123")
	t.Setenv("NEXUS_DEMO_USER_PASSWORD", "user12345")

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_nextgen.db")
	db, err := model.InitDB("sqlite", dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	agentHub := hub.NewAgentHub(db)
	orch := service.NewOrchestrator(db, agentHub)
	srv := NewServer(db, agentHub, orch)
	return srv.SetupRouter(), db, orch, agentHub, srv, func() {
		_ = os.RemoveAll(tmpDir)
	}
}

func startProxyEchoBackend(t *testing.T, expectProxyProto bool) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
				br := bufio.NewReader(conn)
				ver := 0
				clientStr := "none"
				if expectProxyProto {
					v, srcAddr, _, pErr := engine.ParseProxyProtocolHeader(br)
					if pErr != nil {
						_, _ = conn.Write([]byte("PROXY_ERR:" + pErr.Error()))
						return
					}
					ver = v
					clientStr = srcAddr
				}
				var lenBuf [4]byte
				if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
					return
				}
				n := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
				if n <= 0 || n > 4*1024*1024 {
					return
				}
				payload := make([]byte, n)
				if _, err := io.ReadFull(br, payload); err != nil {
					return
				}
				sum := sha256.Sum256(payload)
				resp := fmt.Sprintf("V=%d|CLIENT=%s|LEN=%d|SHA=%s\n", ver, clientStr, len(payload), hex.EncodeToString(sum[:8]))
				_, _ = conn.Write([]byte(resp))
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// TestNextGenMultiHopChainMultipathMuxBondAndProxyProtocolLiveE2E validates:
// 1. Strict loop-free DAG validation on TunnelLine (Ingress/Hop/Egress conflicts, BondLinks bounds, Mux+Bond mutual exclusion).
// 2. Live 3-Hop + Multipath Egress Pool (`Ingress -> Hop1 -> Hop2 -> [Egress1, Egress2]`) with:
//   - Single-stream multi-link chunk striping (`EnableBonding=true, BondLinks=4`) + `PROXY Protocol v2`
//   - Multiplexed persistent TLS pool (`EnableMux=true`) + `PROXY Protocol v1` under 16 concurrent streams
//
// 3. Non-double-billing when Ingress, Hop1, Hop2, and Egress all report traffic deltas for the same rule.
func TestNextGenMultiHopChainMultipathMuxBondAndProxyProtocolLiveE2E(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Setenv("NEXUS_ALLOW_PRIVATE_TARGETS", "true")
	prevAllowPrivate := security.DefaultPolicy.AllowPrivateTargets
	security.DefaultPolicy.AllowPrivateTargets = true
	defer func() { security.DefaultPolicy.AllowPrivateTargets = prevAllowPrivate }()

	r, db, orch, _, _, cleanup := setupNextGenEnv(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	// Create 5 local nodes with isolated high port ranges so 5 native engines can bind concurrently on 127.0.0.1
	createNode := func(name, portRange string) (*model.Node, *security.TunnelCert) {
		w := doJSON(r, http.MethodPost, "/api/v1/admin/nodes", adminTok, map[string]any{
			"name":       name,
			"connect_ip": "127.0.0.1",
			"server_ip":  "127.0.0.1",
			"port_range": portRange,
		}, "")
		if w.Code != http.StatusCreated {
			t.Fatalf("create node %s failed: %d %s", name, w.Code, w.Body.String())
		}
		var created model.Node
		_ = json.Unmarshal(w.Body.Bytes(), &created)

		bundle, err := security.LoadOrCreateTunnelCert(t.TempDir())
		if err != nil {
			t.Fatalf("LoadOrCreateTunnelCert: %v", err)
		}
		db.Model(&model.Node{}).Where("id = ?", created.ID).Updates(map[string]any{
			"tunnel_cert_pem": bundle.CertPEM,
			"status":          "online",
		})
		db.First(&created, created.ID)
		return &created, bundle
	}

	nIn, bIn := createNode("GZ-Ingress", "31000-31199")
	nHop1, bHop1 := createNode("SZ-Hop1", "31200-31399")
	nHop2, bHop2 := createNode("HK-Hop2", "31400-31599")
	nEg1, bEg1 := createNode("SG-Egress1", "31600-31799")
	nEg2, bEg2 := createNode("JP-Egress2", "31800-31999")

	// 1. Adversarial DAG topology & parameter checks
	badLines := []map[string]any{
		{
			"name": "Loop-Ingress-Hop", "type": "encrypt", "engine": "native", "transport": "tls",
			"ingress_node_id": nIn.ID, "hop_node_ids": fmt.Sprintf("%d", nIn.ID), "egress_node_id": nEg1.ID,
			"billing_mode": "two_way", "rate_multiplier": 1.0, "max_port_count": 50,
		},
		{
			"name": "Loop-Dup-Hops", "type": "encrypt", "engine": "native", "transport": "tls",
			"ingress_node_id": nIn.ID, "hop_node_ids": fmt.Sprintf("%d,%d", nHop1.ID, nHop1.ID), "egress_node_id": nEg1.ID,
			"billing_mode": "two_way", "rate_multiplier": 1.0, "max_port_count": 50,
		},
		{
			"name": "Loop-Hop-Egress", "type": "encrypt", "engine": "native", "transport": "tls",
			"ingress_node_id": nIn.ID, "hop_node_ids": fmt.Sprintf("%d", nHop1.ID), "egress_node_ids": fmt.Sprintf("%d:100,%d:100", nEg1.ID, nHop1.ID),
			"billing_mode": "two_way", "rate_multiplier": 1.0, "max_port_count": 50,
		},
		{
			"name": "Both-Mux-And-Bond", "type": "encrypt", "engine": "native", "transport": "tls",
			"ingress_node_id": nIn.ID, "egress_node_id": nEg1.ID, "enable_mux": true, "enable_bonding": true,
			"billing_mode": "two_way", "rate_multiplier": 1.0, "max_port_count": 50,
		},
	}
	for _, bl := range badLines {
		wBad := doJSON(r, http.MethodPost, "/api/v1/admin/lines", adminTok, bl, "")
		if wBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid line %s, got %d: %s", bl["name"], wBad.Code, wBad.Body.String())
		}
	}

	// 2. Create valid 3-Hop + 2-Egress Multipath Bonded + PROXY v2 TunnelLine
	wLine := doJSON(r, http.MethodPost, "/api/v1/admin/lines", adminTok, map[string]any{
		"name":            "3Hop-Bond4-PPv2",
		"type":            "encrypt",
		"engine":          "native",
		"transport":       "tls",
		"ingress_node_id": nIn.ID,
		"hop_node_ids":    fmt.Sprintf("%d,%d", nHop1.ID, nHop2.ID),
		"egress_node_ids": fmt.Sprintf("%d:200,%d:100", nEg1.ID, nEg2.ID),
		"load_balance":    "weighted",
		"enable_bonding":  true,
		"bond_links":      4,
		"proxy_protocol":  2,
		"billing_mode":    "two_way",
		"rate_multiplier": 1.5,
		"max_port_count":  50,
	}, "")
	if wLine.Code != http.StatusCreated {
		t.Fatalf("create 3-hop line failed: %d %s", wLine.Code, wLine.Body.String())
	}
	var line model.TunnelLine
	_ = json.Unmarshal(wLine.Body.Bytes(), &line)

	// Authorize demo user's role group to use this new line
	var demoUser model.User
	db.Where("email = ?", "user@nexus.local").First(&demoUser)
	db.Model(&model.RoleGroup{}).Where("id = ?", demoUser.RoleGroupID).Update("allowed_tunnels", fmt.Sprintf("1,%d", line.ID))
	db.Model(&model.User{}).Where("id = ?", demoUser.ID).Update("allowed_tunnels", fmt.Sprintf("1,%d", line.ID))

	// Non-admin GET /api/v1/lines must hide internal hop_node_ids and egress_node_ids topology
	wUserLines := doJSON(r, http.MethodGet, "/api/v1/lines", userTok, nil, "")
	if wUserLines.Code != http.StatusOK {
		t.Fatalf("GET /lines failed: %d", wUserLines.Code)
	}
	var userVisibleLines []model.TunnelLine
	_ = json.Unmarshal(wUserLines.Body.Bytes(), &userVisibleLines)
	for _, ul := range userVisibleLines {
		if ul.ID == line.ID && (ul.HopNodeIDs != "" || ul.EgressNodeIDs != "") {
			t.Fatalf("non-admin /lines leaked internal hop/egress node IDs: %+v", ul)
		}
	}

	// Start backend TCP echo server expecting PROXY Protocol header
	backendAddr, closeBackend := startProxyEchoBackend(t, true)
	defer closeBackend()

	// Create ForwardRule on the 3-hop line
	wRule := doJSON(r, http.MethodPost, "/api/v1/rules", userTok, map[string]any{
		"name":           "3Hop-Live-Rule",
		"mode":           "tunnel",
		"tunnel_line_id": line.ID,
		"protocol":       "tcp",
		"listen_port":    0,
		"load_balance":   "round_robin",
		"targets":        []map[string]any{{"address": backendAddr}},
	}, "")
	if wRule.Code != http.StatusCreated {
		t.Fatalf("create rule failed: %d %s", wRule.Code, wRule.Body.String())
	}
	var rule model.ForwardRule
	_ = json.Unmarshal(wRule.Body.Bytes(), &rule)
	db.First(&rule, rule.ID)
	if len(rule.HopPortAllocs()) != 2 || len(rule.EgressPortAllocs()) != 2 {
		t.Fatalf("expected 2 hop ports & 2 egress ports allocated, got hops=%v egress=%v", rule.HopPortsJSON, rule.EgressPortsJSON)
	}

	// Compile full rule graph & spin up 5 real NativeDriver instances
	compiled, err := orch.CompileRuleGraph(&rule)
	if err != nil {
		t.Fatalf("CompileRuleGraph: %v", err)
	}
	if len(compiled) != 5 {
		t.Fatalf("expected 5 compiled node specs (Ingress + 2 Hops + 2 Egresses), got %d", len(compiled))
	}

	pol := security.Policy{AllowPrivateTargets: true, MinListenPort: 1024, MaxListenPort: 65535, MaxConnsPerClientIP: 256}
	drivers := map[uint64]*engine.NativeEngine{
		nIn.ID:   engine.NewNativeEngine(pol, bIn),
		nHop1.ID: engine.NewNativeEngine(pol, bHop1),
		nHop2.ID: engine.NewNativeEngine(pol, bHop2),
		nEg1.ID:  engine.NewNativeEngine(pol, bEg1),
		nEg2.ID:  engine.NewNativeEngine(pol, bEg2),
	}
	for _, drv := range drivers {
		defer drv.Close()
	}
	for _, ns := range compiled {
		if err := drivers[ns.NodeID].ApplyRule(ctx, ns.Spec); err != nil {
			t.Fatalf("ApplyRule on node %d (%s) failed: %v", ns.NodeID, ns.Spec.Role, err)
		}
	}

	// Dial Ingress across 3-hop Bonded(4 links) + Multipath Egress + PROXY v2!
	sendAndVerify := func(wantVer int, payloadSize int) {
		conn, dErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", rule.ListenPort), 5*time.Second)
		if dErr != nil {
			t.Fatalf("dial ingress: %v", dErr)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

		localAddr := conn.LocalAddr().String()
		buf := make([]byte, payloadSize)
		for i := range buf {
			buf[i] = byte((i*31 + 7) & 0xff)
		}
		sum := sha256.Sum256(buf)
		wantSHA := hex.EncodeToString(sum[:8])

		var hdr [4]byte
		hdr[0] = byte(payloadSize >> 24)
		hdr[1] = byte(payloadSize >> 16)
		hdr[2] = byte(payloadSize >> 8)
		hdr[3] = byte(payloadSize)
		if _, err := conn.Write(hdr[:]); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := conn.Write(buf); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		respBytes, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		resp := strings.TrimSpace(string(respBytes))
		want := fmt.Sprintf("V=%d|CLIENT=%s|LEN=%d|SHA=%s", wantVer, localAddr, payloadSize, wantSHA)
		if resp != want {
			t.Fatalf("3-hop E2E mismatch:\n got: %q\nwant: %q", resp, want)
		}
	}

	// Verify 128 KiB striped across 4 bonded links over 3 hops preserves exact bytes AND client IP via PROXY v2!
	for i := 0; i < 4; i++ {
		sendAndVerify(2, 128*1024)
	}

	// 3. Switch line to EnableMux=true + PROXY Protocol v1 and verify 16 concurrent streams!
	wUpdLine := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/lines/%d", line.ID), adminTok, map[string]any{
		"name":            "3Hop-Mux-PPv1",
		"type":            "encrypt",
		"engine":          "native",
		"transport":       "tls",
		"ingress_node_id": nIn.ID,
		"hop_node_ids":    fmt.Sprintf("%d,%d", nHop1.ID, nHop2.ID),
		"egress_node_ids": fmt.Sprintf("%d:200,%d:100", nEg1.ID, nEg2.ID),
		"load_balance":    "round_robin",
		"enable_mux":      true,
		"enable_bonding":  false,
		"proxy_protocol":  1,
		"billing_mode":    "two_way",
		"rate_multiplier": 1.5,
		"max_port_count":  50,
	}, "")
	if wUpdLine.Code != http.StatusOK {
		t.Fatalf("update line to Mux+PPv1 failed: %d %s", wUpdLine.Code, wUpdLine.Body.String())
	}
	db.First(&rule, rule.ID)
	compiledMux, err := orch.CompileRuleGraph(&rule)
	if err != nil {
		t.Fatalf("CompileRuleGraph mux: %v", err)
	}
	for _, ns := range compiledMux {
		if err := drivers[ns.NodeID].ApplyRule(ctx, ns.Spec); err != nil {
			t.Fatalf("ApplyRule mux on node %d (%s) failed: %v", ns.NodeID, ns.Spec.Role, err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendAndVerify(1, 48*1024)
		}()
	}
	wg.Wait()

	// 4. Verify Non-Double-Billing when Ingress + Hop1 + Hop2 + Egress1 all report 1,000,000 bytes!
	var userBefore model.User
	db.First(&userBefore, demoUser.ID)
	nowUnix := time.Now().Unix()

	orch.HandleTrafficReport(nIn.ID, protocol.TrafficReportPayload{
		Timestamp: nowUnix,
		Deltas: []protocol.RuleTrafficDelta{{
			RuleID: rule.ID, Role: protocol.RoleIngress, UploadBytes: 400_000, DownBytes: 600_000,
		}},
	})
	orch.HandleTrafficReport(nHop1.ID, protocol.TrafficReportPayload{
		Timestamp: nowUnix,
		Deltas: []protocol.RuleTrafficDelta{{
			RuleID: rule.ID, Role: protocol.RoleHop(0), UploadBytes: 400_000, DownBytes: 600_000,
		}},
	})
	orch.HandleTrafficReport(nHop2.ID, protocol.TrafficReportPayload{
		Timestamp: nowUnix,
		Deltas: []protocol.RuleTrafficDelta{{
			RuleID: rule.ID, Role: protocol.RoleHop(1), UploadBytes: 400_000, DownBytes: 600_000,
		}},
	})
	orch.HandleTrafficReport(nEg1.ID, protocol.TrafficReportPayload{
		Timestamp: nowUnix,
		Deltas: []protocol.RuleTrafficDelta{{
			RuleID: rule.ID, Role: protocol.RoleEgress, UploadBytes: 400_000, DownBytes: 600_000,
		}},
	})
	// Out-of-scope spoofed report from nEg2 claiming RoleHop(0) must be completely ignored!
	orch.HandleTrafficReport(nEg2.ID, protocol.TrafficReportPayload{
		Timestamp: nowUnix,
		Deltas: []protocol.RuleTrafficDelta{{
			RuleID: rule.ID, Role: protocol.RoleHop(0), UploadBytes: 9_000_000, DownBytes: 9_000_000,
		}},
	})

	var userAfter model.User
	db.First(&userAfter, demoUser.ID)
	var ruleAfter model.ForwardRule
	db.First(&ruleAfter, rule.ID)

	// Billed once on RoleIngress: (400_000 + 600_000) * 1.5 (line) * 1.0 (node) = 1,500,000
	if ruleAfter.BilledBytes != 1_500_000 {
		t.Fatalf("expected rule BilledBytes=1500000 (non-double-billed), got %d", ruleAfter.BilledBytes)
	}
	if userAfter.UsedBytes-userBefore.UsedBytes != 1_500_000 {
		t.Fatalf("expected user UsedBytes delta=1500000, got %d", userAfter.UsedBytes-userBefore.UsedBytes)
	}

	// Physical node bandwidth must be counted on nIn, nHop1, nHop2, nEg1 (1,000,000 each), and 0 on nEg2!
	for _, checkID := range []uint64{nIn.ID, nHop1.ID, nHop2.ID, nEg1.ID} {
		var nd model.Node
		db.First(&nd, checkID)
		if nd.UsedBytes != 1_000_000 {
			t.Fatalf("expected physical node #%d UsedBytes=1000000, got %d", checkID, nd.UsedBytes)
		}
	}
	var ndEg2 model.Node
	db.First(&ndEg2, nEg2.ID)
	if ndEg2.UsedBytes != 0 {
		t.Fatalf("expected spoofed RoleHop report on nEg2 to be rejected (UsedBytes=0), got %d", ndEg2.UsedBytes)
	}
}

// TestNextGenSNISharedPortRoutingAndConflictGuards validates multi-tenant shared-port SNI/Host routing,
// overlap/wildcard hijacking prevention, exclusive-vs-shared isolation, and grouped port-range migration.
func TestNextGenSNISharedPortRoutingAndConflictGuards(t *testing.T) {
	r, db, _, _, _, cleanup := setupNextGenEnv(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	aliceTok := login(t, r, "user@nexus.local", "user12345")

	// Create second tenant Bob on the same role group
	wBob := doJSON(r, http.MethodPost, "/api/v1/admin/users", adminTok, map[string]any{
		"email":           "bob@nexus.local",
		"password":        "bobpass123",
		"role":            "user",
		"role_group_id":   1,
		"allowed_tunnels": "1",
		"quota_bytes":     100 * 1024 * 1024 * 1024,
		"max_rules":       20,
		"speed_mbps":      100,
	}, "")
	if wBob.Code != http.StatusCreated {
		t.Fatalf("create bob failed: %d %s", wBob.Code, wBob.Body.String())
	}
	bobTok := login(t, r, "bob@nexus.local", "bobpass123")

	// Alice creates SNI rule on shared port 24443
	wAlice := doJSON(r, http.MethodPost, "/api/v1/rules", aliceTok, map[string]any{
		"name":           "Alice-SNI",
		"mode":           "direct",
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"listen_port":    24443,
		"match_domains":  "alice.example.com, *.alice-cdn.example.com",
		"load_balance":   "round_robin",
		"targets":        []map[string]any{{"address": "1.1.1.1:443"}},
	}, "")
	if wAlice.Code != http.StatusCreated {
		t.Fatalf("Alice SNI rule create failed: %d %s", wAlice.Code, wAlice.Body.String())
	}
	var aliceRule model.ForwardRule
	_ = json.Unmarshal(wAlice.Body.Bytes(), &aliceRule)

	// Bob shares port 24443 with a disjoint domain -> MUST SUCCEED (201)!
	wBobOK := doJSON(r, http.MethodPost, "/api/v1/rules", bobTok, map[string]any{
		"name":           "Bob-SNI",
		"mode":           "direct",
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"listen_port":    24443,
		"match_domains":  "bob.example.com",
		"load_balance":   "round_robin",
		"targets":        []map[string]any{{"address": "8.8.8.8:443"}},
	}, "")
	if wBobOK.Code != http.StatusCreated {
		t.Fatalf("Bob disjoint SNI rule on shared port 24443 failed: %d %s", wBobOK.Code, wBobOK.Body.String())
	}
	var bobRule model.ForwardRule
	_ = json.Unmarshal(wBobOK.Body.Bytes(), &bobRule)

	// Hijack attempt 1: Bob tries subdomain covered by Alice's *.alice-cdn.example.com -> 400 Bad Request
	wHijack1 := doJSON(r, http.MethodPost, "/api/v1/rules", bobTok, map[string]any{
		"name":           "Bob-Hijack-Sub",
		"mode":           "direct",
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"listen_port":    24443,
		"match_domains":  "edge.alice-cdn.example.com",
		"load_balance":   "round_robin",
		"targets":        []map[string]any{{"address": "8.8.4.4:443"}},
	}, "")
	if wHijack1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when overlapping Alice's wildcard domain, got %d: %s", wHijack1.Code, wHijack1.Body.String())
	}

	// Hijack attempt 2: Bob tries parent wildcard *.example.com overlapping alice.example.com -> 400 Bad Request
	wHijack2 := doJSON(r, http.MethodPost, "/api/v1/rules", bobTok, map[string]any{
		"name":           "Bob-Hijack-Wildcard",
		"mode":           "direct",
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"listen_port":    24443,
		"match_domains":  "*.example.com",
		"load_balance":   "round_robin",
		"targets":        []map[string]any{{"address": "8.8.4.4:443"}},
	}, "")
	if wHijack2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when wildcard overlaps existing domain, got %d: %s", wHijack2.Code, wHijack2.Body.String())
	}

	// Hijack attempt 3: Exclusive non-domain rule on shared port 24443 -> 400 Bad Request
	wExclConflict := doJSON(r, http.MethodPost, "/api/v1/rules", bobTok, map[string]any{
		"name":           "Bob-Exclusive-On-Shared",
		"mode":           "direct",
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"listen_port":    24443,
		"load_balance":   "round_robin",
		"targets":        []map[string]any{{"address": "8.8.4.4:443"}},
	}, "")
	if wExclConflict.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for exclusive rule on SNI shared port, got %d", wExclConflict.Code)
	}

	// Non-TCP (UDP) with MatchDomains -> 400 Bad Request
	wUDP := doJSON(r, http.MethodPost, "/api/v1/rules", bobTok, map[string]any{
		"name":           "UDP-SNI-Invalid",
		"mode":           "direct",
		"tunnel_line_id": 1,
		"protocol":       "udp",
		"listen_port":    24445,
		"match_domains":  "dns.example.com",
		"load_balance":   "round_robin",
		"targets":        []map[string]any{{"address": "8.8.8.8:53"}},
	}, "")
	if wUDP.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for UDP rule with MatchDomains, got %d", wUDP.Code)
	}

	// Grouped Port-Range Migration: shrink Ingress Node #1 port range to 26000-26100 -> Alice & Bob must move TOGETHER!
	var line1 model.TunnelLine
	db.First(&line1, 1)
	if line1.PortRange != "" {
		db.Model(&model.TunnelLine{}).Where("id = ?", line1.ID).Update("port_range", "")
	}
	wShrink := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", line1.IngressNodeID), adminTok, map[string]any{
		"port_range": "26000-26100",
	}, "")
	if wShrink.Code != http.StatusOK {
		t.Fatalf("shrink node port range failed: %d %s", wShrink.Code, wShrink.Body.String())
	}
	var aliceMoved, bobMoved model.ForwardRule
	db.First(&aliceMoved, aliceRule.ID)
	db.First(&bobMoved, bobRule.ID)
	if aliceMoved.ListenPort < 26000 || aliceMoved.ListenPort > 26100 {
		t.Fatalf("Alice rule did not migrate into 26000-26100, got %d", aliceMoved.ListenPort)
	}
	if aliceMoved.ListenPort != bobMoved.ListenPort {
		t.Fatalf("shared-port SNI rules split apart on port range migration: Alice=%d Bob=%d", aliceMoved.ListenPort, bobMoved.ListenPort)
	}

	// Also verify TunnelLine PortRange narrowing via PUT /api/v1/admin/lines/:id keeps shared-port SNI rules together!
	wLineNarrow := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/lines/%d", line1.ID), adminTok, map[string]any{
		"name":            line1.Name,
		"type":            line1.Type,
		"ingress_node_id": line1.IngressNodeID,
		"port_range":      "26050-26090",
		"enabled":         true,
	}, "")
	if wLineNarrow.Code != http.StatusOK {
		t.Fatalf("narrow tunnel line port range failed: %d %s", wLineNarrow.Code, wLineNarrow.Body.String())
	}
	db.First(&aliceMoved, aliceRule.ID)
	db.First(&bobMoved, bobRule.ID)
	if aliceMoved.ListenPort < 26050 || aliceMoved.ListenPort > 26090 || aliceMoved.ListenPort != bobMoved.ListenPort {
		t.Fatalf("shared-port SNI rules split apart on line port range update: Alice=%d Bob=%d", aliceMoved.ListenPort, bobMoved.ListenPort)
	}
}

// TestNextGenOutboundIPRBACAndTargetSanitization verifies OutboundIP RBAC enforcement and client TargetEndpoint sanitization.
func TestNextGenOutboundIPRBACAndTargetSanitization(t *testing.T) {
	r, db, _, _, _, cleanup := setupNextGenEnv(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	var line1 model.TunnelLine
	db.First(&line1, 1)

	// Loopback outbound IP rejected in production mode
	wLoop := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", line1.IngressNodeID), adminTok, map[string]any{
		"outbound_ip": "127.0.0.1",
	}, "")
	if wLoop.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for loopback outbound_ip in production mode, got %d", wLoop.Code)
	}

	// Authorize two public outbound IPs on the node
	wAllow := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", line1.IngressNodeID), adminTok, map[string]any{
		"outbound_ip":          "198.51.100.10",
		"allowed_outbound_ips": "198.51.100.10, 198.51.100.11",
	}, "")
	if wAllow.Code != http.StatusOK {
		t.Fatalf("update node outbound IPs failed: %d %s", wAllow.Code, wAllow.Body.String())
	}

	// Non-admin tries unauthorized outbound IP -> 403 Forbidden
	wForbidden := doJSON(r, http.MethodPost, "/api/v1/rules", userTok, map[string]any{
		"name":           "Unauth-OutboundIP",
		"mode":           "direct",
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"listen_port":    0,
		"outbound_ip":    "198.51.100.99",
		"load_balance":   "round_robin",
		"targets":        []map[string]any{{"address": "1.1.1.1:443"}},
	}, "")
	if wForbidden.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unauthorized outbound_ip by non-admin, got %d: %s", wForbidden.Code, wForbidden.Body.String())
	}

	// Non-admin picks authorized outbound IP AND attempts to smuggle CertPEM & NodeID in targets -> 201 Created, smuggled fields stripped!
	wOK := doJSON(r, http.MethodPost, "/api/v1/rules", userTok, map[string]any{
		"name":           "Auth-OutboundIP-Sanitized",
		"mode":           "direct",
		"tunnel_line_id": 1,
		"protocol":       "tcp",
		"listen_port":    0,
		"outbound_ip":    "198.51.100.11",
		"load_balance":   "weighted",
		"targets": []map[string]any{{
			"address":  "1.1.1.1:443",
			"weight":   200,
			"cert_pem": "-----BEGIN CERTIFICATE-----\nINJECTED\n-----END CERTIFICATE-----",
			"node_id":  999,
		}},
	}, "")
	if wOK.Code != http.StatusCreated {
		t.Fatalf("expected 201 for authorized outbound_ip, got %d: %s", wOK.Code, wOK.Body.String())
	}
	var created model.ForwardRule
	_ = json.Unmarshal(wOK.Body.Bytes(), &created)
	var stored model.ForwardRule
	db.First(&stored, created.ID)
	if strings.Contains(stored.TargetsJSON, "BEGIN CERTIFICATE") || strings.Contains(stored.TargetsJSON, "999") {
		t.Fatalf("SECURITY FAILURE: client-supplied cert_pem or node_id persisted in TargetsJSON: %s", stored.TargetsJSON)
	}
}

// TestNextGenOffPeakDynamicBillingAndRuleDailyQuotas verifies cross-midnight off-peak multipliers,
// anti-spoof timestamp skew protection, daily quota cutoff + next-day auto-resume, and total rule quota cap.
func TestNextGenOffPeakDynamicBillingAndRuleDailyQuotas(t *testing.T) {
	r, db, orch, _, _, cleanup := setupNextGenEnv(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	// 1. Unit verify cross-midnight window (23:00 - 07:00 Asia/Shanghai)
	cfg := &model.SystemConfig{
		OffPeakEnabled:    true,
		OffPeakStart:      "23:00",
		OffPeakEnd:        "07:00",
		OffPeakMultiplier: 0.25,
		OffPeakTimezone:   "Asia/Shanghai",
	}
	loc, _ := time.LoadLocation("Asia/Shanghai")
	tLateNight := time.Date(2026, 5, 10, 23, 30, 0, 0, loc)
	tEarlyMorn := time.Date(2026, 5, 11, 6, 45, 0, 0, loc)
	tDaytime := time.Date(2026, 5, 11, 14, 0, 0, 0, loc)
	if f := service.ComputeOffPeakFactor(cfg, nil, tLateNight); f != 0.25 {
		t.Fatalf("expected 0.25 at 23:30, got %v", f)
	}
	if f := service.ComputeOffPeakFactor(cfg, nil, tEarlyMorn); f != 0.25 {
		t.Fatalf("expected 0.25 at 06:45, got %v", f)
	}
	if f := service.ComputeOffPeakFactor(cfg, nil, tDaytime); f != 1.0 {
		t.Fatalf("expected 1.0 at 14:00, got %v", f)
	}
	overrideLine := &model.TunnelLine{OffPeakMultiplier: 0.1}
	if f := service.ComputeOffPeakFactor(cfg, overrideLine, tLateNight); f != 0.1 {
		t.Fatalf("expected line override 0.1 at 23:30, got %v", f)
	}

	// 2. Configure 00:00 - 23:59 off-peak 0.5x via Admin Settings API to test live HandleTrafficReport scaling & quotas
	wSet := doJSON(r, http.MethodPut, "/api/v1/admin/settings", adminTok, map[string]any{
		"site_name":          "Zachary Panel",
		"offpeak_enabled":    true,
		"offpeak_start":      "00:00",
		"offpeak_end":        "23:59",
		"offpeak_multiplier": 0.5,
		"offpeak_timezone":   "UTC",
	}, "")
	if wSet.Code != http.StatusOK {
		t.Fatalf("update offpeak settings failed: %d %s", wSet.Code, wSet.Body.String())
	}

	// Create rule with DailyQuota = 50_000 bytes, RuleQuota = 120_000 bytes
	wRule := doJSON(r, http.MethodPost, "/api/v1/rules", userTok, map[string]any{
		"name":              "Quota-Capped-Rule",
		"mode":              "direct",
		"tunnel_line_id":    1,
		"protocol":          "tcp",
		"listen_port":       0,
		"load_balance":      "round_robin",
		"daily_quota_bytes": 50_000,
		"rule_quota_bytes":  120_000,
		"targets":           []map[string]any{{"address": "1.1.1.1:443"}},
	}, "")
	if wRule.Code != http.StatusCreated {
		t.Fatalf("create quota rule failed: %d %s", wRule.Code, wRule.Body.String())
	}
	var rule model.ForwardRule
	_ = json.Unmarshal(wRule.Body.Bytes(), &rule)

	var line1 model.TunnelLine
	db.First(&line1, 1)
	db.Model(&model.TunnelLine{}).Where("id = ?", line1.ID).Updates(map[string]any{
		"billing_mode":    "two_way",
		"rate_multiplier": 1.0,
	})
	db.Model(&model.Node{}).Where("id = ?", line1.IngressNodeID).Update("traffic_rate", 1.0)

	// Report 120_000 raw bytes -> at 0.5x off-peak = 60_000 billed bytes (>= 50_000 daily quota!)
	orch.HandleTrafficReport(line1.IngressNodeID, protocol.TrafficReportPayload{
		Timestamp: time.Now().Unix(),
		Deltas: []protocol.RuleTrafficDelta{{
			RuleID: rule.ID, Role: protocol.RoleIngress, UploadBytes: 60_000, DownBytes: 60_000,
		}},
	})
	db.First(&rule, rule.ID)
	if rule.BilledBytes != 60_000 || rule.DailyUsedBytes != 60_000 {
		t.Fatalf("expected 60000 billed/daily bytes with 0.5x off-peak, got billed=%d daily=%d", rule.BilledBytes, rule.DailyUsedBytes)
	}
	if rule.Enabled || rule.Status != "daily_quota_exceeded" {
		t.Fatalf("expected daily_quota_exceeded pause, got enabled=%v status=%s", rule.Enabled, rule.Status)
	}

	// Next-day rollover via ProcessPeriodicResets must reset DailyUsedBytes=0 and auto-resume the rule!
	tomorrow := time.Now().UTC().Add(26 * time.Hour)
	orch.ProcessPeriodicResets(tomorrow)
	db.First(&rule, rule.ID)
	if !rule.Enabled || (rule.Status != "running" && rule.Status != "syncing") || rule.DailyUsedBytes != 0 {
		t.Fatalf("expected rule auto-resumed on next-day rollover, got enabled=%v status=%s daily=%d", rule.Enabled, rule.Status, rule.DailyUsedBytes)
	}

	// Report another 140_000 raw bytes -> +70_000 billed -> cumulative 130_000 >= 120_000 RuleQuotaBytes!
	orch.HandleTrafficReport(line1.IngressNodeID, protocol.TrafficReportPayload{
		Timestamp: time.Now().Unix(),
		Deltas: []protocol.RuleTrafficDelta{{
			RuleID: rule.ID, Role: protocol.RoleIngress, UploadBytes: 70_000, DownBytes: 70_000,
		}},
	})
	db.First(&rule, rule.ID)
	if rule.Enabled || rule.Status != "rule_quota_exceeded" {
		t.Fatalf("expected rule_quota_exceeded pause, got enabled=%v status=%s", rule.Enabled, rule.Status)
	}

	// Subsequent daily rollover must NOT resume a rule that hit total RuleQuotaBytes!
	dayAfter := tomorrow.Add(26 * time.Hour)
	orch.ProcessPeriodicResets(dayAfter)
	db.First(&rule, rule.ID)
	if rule.Enabled || rule.Status != "rule_quota_exceeded" {
		t.Fatalf("rule_quota_exceeded must stay paused across daily rollover, got enabled=%v status=%s", rule.Enabled, rule.Status)
	}
}

// TestNextGenMultiIngressDNSFailoverProvidersAndAntiFlap validates Cloudflare, DNSPod, and HMAC-signed Webhook
// automatic DNS failover, offline threshold, anti-flap cooldown, auto-failback, maintenance trigger, and secret masking.
func TestNextGenMultiIngressDNSFailoverProvidersAndAntiFlap(t *testing.T) {
	r, db, orch, _, _, cleanup := setupNextGenEnv(t)
	defer cleanup()

	adminTok := login(t, r, "admin@nexus.local", "admin123")

	// Create Primary (203.0.113.10) and Backup (203.0.113.20) ingress nodes
	makeIngress := func(name, ip string) model.Node {
		w := doJSON(r, http.MethodPost, "/api/v1/admin/nodes", adminTok, map[string]any{
			"name":       name,
			"connect_ip": ip,
			"server_ip":  ip,
			"port_range": "20000-30000",
		}, "")
		if w.Code != http.StatusCreated {
			t.Fatalf("create node %s: %d %s", name, w.Code, w.Body.String())
		}
		var n model.Node
		_ = json.Unmarshal(w.Body.Bytes(), &n)
		now := time.Now()
		db.Model(&model.Node{}).Where("id = ?", n.ID).Updates(map[string]any{"status": "online", "last_seen_at": &now})
		db.First(&n, n.ID)
		return n
	}
	nPrimary := makeIngress("CF-Primary", "203.0.113.10")
	nBackup := makeIngress("CF-Backup", "203.0.113.20")

	// SSRF check BEFORE enabling test override: private webhook URL must be rejected!
	wSSRF := doJSON(r, http.MethodPost, "/api/v1/admin/dns-failover", adminTok, map[string]any{
		"name":            "SSRF-Attempt",
		"domain":          "entry.example.com",
		"record_type":     "A",
		"primary_node_id": nPrimary.ID,
		"backup_node_ids": fmt.Sprintf("%d", nBackup.ID),
		"provider":        "webhook",
		"webhook_url":     "http://127.0.0.1:9999/internal",
	}, "")
	if wSSRF.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 SSRF block for localhost webhook URL, got %d: %s", wSSRF.Code, wSSRF.Body.String())
	}

	// Stand up mock Cloudflare, DNSPod, and signed Webhook servers
	var cfMu sync.Mutex
	var cfPutIPs []string
	cfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer cf-secret-token-999" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if req.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"rec_auto_123"}]}`))
			return
		}
		if req.Method == http.MethodPut && strings.HasSuffix(req.URL.Path, "/dns_records/rec_auto_123") {
			var body struct {
				Content string `json:"content"`
			}
			_ = json.NewDecoder(req.Body).Decode(&body)
			cfMu.Lock()
			cfPutIPs = append(cfPutIPs, body.Content)
			cfMu.Unlock()
			_, _ = w.Write([]byte(`{"success":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer cfSrv.Close()

	var dpLastValue string
	dpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		if req.FormValue("login_token") != "10086,dp_secret_abc" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(req.URL.Path, "/Record.List") {
			_, _ = w.Write([]byte(`{"status":{"code":"1"},"records":[{"id":"778899","type":"A"}]}`))
			return
		}
		if strings.HasSuffix(req.URL.Path, "/Record.Modify") {
			dpLastValue = req.FormValue("value")
			_, _ = w.Write([]byte(`{"status":{"code":"1"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer dpSrv.Close()

	defer orch.WaitBackground()

	const whSecret = "dns-hook-hmac-key"
	var whMu sync.Mutex
	var whSigValid bool
	var whIP string
	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		mac := hmac.New(sha256.New, []byte(whSecret))
		mac.Write(raw)
		wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		var p struct {
			NewIP string `json:"new_ip"`
		}
		_ = json.Unmarshal(raw, &p)
		whMu.Lock()
		whSigValid = hmac.Equal([]byte(req.Header.Get("X-Zachary-Signature")), []byte(wantSig))
		whIP = p.NewIP
		whMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer whSrv.Close()

	orch.SetDNSProviderOverrideForTest(cfSrv.Client(), cfSrv.URL, dpSrv.URL)

	// 1. Create Cloudflare Failover Group & verify APIToken is masked in API responses
	wCF := doJSON(r, http.MethodPost, "/api/v1/admin/dns-failover", adminTok, map[string]any{
		"name":                  "HK-CF-HA",
		"domain":                "hk-entry.example.com",
		"record_type":           "A",
		"ttl":                   60,
		"primary_node_id":       nPrimary.ID,
		"backup_node_ids":       fmt.Sprintf("%d", nBackup.ID),
		"provider":              "cloudflare",
		"zone_id":               "zone_abc_123",
		"api_token":             "cf-secret-token-999",
		"offline_threshold_sec": 30,
		"cooldown_sec":          120,
		"auto_failback":         true,
		"enabled":               true,
	}, "")
	if wCF.Code != http.StatusCreated {
		t.Fatalf("create CF failover group failed: %d %s", wCF.Code, wCF.Body.String())
	}
	if strings.Contains(wCF.Body.String(), "cf-secret-token-999") {
		t.Fatalf("SECURITY FAILURE: api_token leaked in response: %s", wCF.Body.String())
	}
	var cfGroup model.IngressFailoverGroup
	_ = json.Unmarshal(wCF.Body.Bytes(), &cfGroup)
	if !cfGroup.HasAPIToken {
		t.Fatalf("expected has_api_token=true")
	}

	baseT := time.Now()
	// Initial sync: Primary is online -> auto-discovers rec_auto_123 and sets 203.0.113.10
	orch.EvaluateDNSFailoverGroups(baseT)
	db.First(&cfGroup, cfGroup.ID)
	if cfGroup.ActiveNodeID != nPrimary.ID || cfGroup.ActiveIP != "203.0.113.10" || cfGroup.RecordID != "rec_auto_123" {
		t.Fatalf("initial CF sync unexpected: %+v", cfGroup)
	}

	// Primary offline for 10s (< 30s threshold) -> must NOT flap!
	t10sAgo := baseT.Add(15 * time.Second)
	seen5sAgo := t10sAgo.Add(-10 * time.Second)
	db.Model(&model.Node{}).Where("id = ?", nPrimary.ID).Updates(map[string]any{"status": "offline", "last_seen_at": &seen5sAgo})
	db.Model(&model.Node{}).Where("id = ?", nBackup.ID).Updates(map[string]any{"status": "online", "last_seen_at": &t10sAgo})
	orch.EvaluateDNSFailoverGroups(t10sAgo)
	db.First(&cfGroup, cfGroup.ID)
	if cfGroup.ActiveNodeID != nPrimary.ID {
		t.Fatalf("expected no flap below threshold, but switched to %d", cfGroup.ActiveNodeID)
	}

	// Primary offline for 45s (> 30s threshold) & past cooldown -> switches to Backup (203.0.113.20)!
	tFail := baseT.Add(150 * time.Second)
	seen45sAgo := tFail.Add(-45 * time.Second)
	db.Model(&model.Node{}).Where("id = ?", nPrimary.ID).Updates(map[string]any{"status": "offline", "last_seen_at": &seen45sAgo})
	db.Model(&model.Node{}).Where("id = ?", nBackup.ID).Updates(map[string]any{"status": "online", "last_seen_at": &tFail})
	orch.EvaluateDNSFailoverGroups(tFail)
	db.First(&cfGroup, cfGroup.ID)
	if cfGroup.ActiveNodeID != nBackup.ID || cfGroup.ActiveIP != "203.0.113.20" {
		t.Fatalf("expected failover to Backup, got active=%d ip=%s err=%s", cfGroup.ActiveNodeID, cfGroup.ActiveIP, cfGroup.LastError)
	}

	// Primary recovers 20s later (< 120s cooldown) -> anti-flap cooldown blocks immediate failback!
	tRecoverEarly := tFail.Add(20 * time.Second)
	db.Model(&model.Node{}).Where("id = ?", nPrimary.ID).Updates(map[string]any{"status": "online", "last_seen_at": &tRecoverEarly})
	db.Model(&model.Node{}).Where("id = ?", nBackup.ID).Updates(map[string]any{"status": "online", "last_seen_at": &tRecoverEarly})
	orch.EvaluateDNSFailoverGroups(tRecoverEarly)
	db.First(&cfGroup, cfGroup.ID)
	if cfGroup.ActiveNodeID != nBackup.ID {
		t.Fatalf("cooldown failed to prevent early failback")
	}

	// Cooldown expires (tFail + 130s) -> AutoFailback returns DNS to Primary (203.0.113.10)!
	tFailback := tFail.Add(130 * time.Second)
	db.Model(&model.Node{}).Where("id = ?", nPrimary.ID).Updates(map[string]any{"status": "online", "last_seen_at": &tFailback})
	db.Model(&model.Node{}).Where("id = ?", nBackup.ID).Updates(map[string]any{"status": "online", "last_seen_at": &tFailback})
	orch.EvaluateDNSFailoverGroups(tFailback)
	db.First(&cfGroup, cfGroup.ID)
	if cfGroup.ActiveNodeID != nPrimary.ID || cfGroup.ActiveIP != "203.0.113.10" {
		t.Fatalf("expected auto-failback to Primary, got active=%d ip=%s", cfGroup.ActiveNodeID, cfGroup.ActiveIP)
	}

	// 2. Verify DNSPod provider auto-discovery & switch
	wDP := doJSON(r, http.MethodPost, "/api/v1/admin/dns-failover", adminTok, map[string]any{
		"name":            "GZ-DNSPod-HA",
		"domain":          "gz.example.com",
		"record_type":     "A",
		"primary_node_id": nPrimary.ID,
		"backup_node_ids": fmt.Sprintf("%d", nBackup.ID),
		"provider":        "dnspod",
		"api_token":       "10086,dp_secret_abc",
	}, "")
	if wDP.Code != http.StatusCreated {
		t.Fatalf("create DNSPod group failed: %d %s", wDP.Code, wDP.Body.String())
	}
	var dpGroup model.IngressFailoverGroup
	_ = json.Unmarshal(wDP.Body.Bytes(), &dpGroup)
	wRecDP := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/dns-failover/%d/reconcile", dpGroup.ID), adminTok, map[string]any{
		"target_node_id": nBackup.ID,
	}, "")
	if wRecDP.Code != http.StatusOK || dpLastValue != "203.0.113.20" {
		t.Fatalf("DNSPod manual reconcile failed: code=%d val=%q body=%s", wRecDP.Code, dpLastValue, wRecDP.Body.String())
	}

	// 3. Verify HMAC-signed Custom Webhook provider (allow private targets temporarily for local httptest webhook URL)
	prevPriv := security.DefaultPolicy.AllowPrivateTargets
	security.DefaultPolicy.AllowPrivateTargets = true
	defer func() { security.DefaultPolicy.AllowPrivateTargets = prevPriv }()

	wWH := doJSON(r, http.MethodPost, "/api/v1/admin/dns-failover", adminTok, map[string]any{
		"name":            "WH-Custom-DNS",
		"domain":          "wh.example.com",
		"record_type":     "A",
		"primary_node_id": nPrimary.ID,
		"backup_node_ids": fmt.Sprintf("%d", nBackup.ID),
		"provider":        "webhook",
		"webhook_url":     whSrv.URL,
		"api_token":       whSecret,
	}, "")
	if wWH.Code != http.StatusCreated {
		t.Fatalf("create Webhook DNS group failed: %d %s", wWH.Code, wWH.Body.String())
	}
	var whGroup model.IngressFailoverGroup
	_ = json.Unmarshal(wWH.Body.Bytes(), &whGroup)
	wRecWH := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/dns-failover/%d/reconcile", whGroup.ID), adminTok, nil, "")
	whMu.Lock()
	sig1, ip1 := whSigValid, whIP
	whMu.Unlock()
	if wRecWH.Code != http.StatusOK || !sig1 || ip1 != "203.0.113.10" {
		t.Fatalf("Webhook DNS reconcile failed: code=%d sigValid=%v ip=%q body=%s", wRecWH.Code, sig1, ip1, wRecWH.Body.String())
	}

	// Put Primary into maintenance mode via Admin API -> drains to Backup (203.0.113.20)
	wMaint := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", nPrimary.ID), adminTok, map[string]any{
		"status": "maintenance",
	}, "")
	if wMaint.Code != http.StatusOK {
		t.Fatalf("set node maintenance failed: %d %s", wMaint.Code, wMaint.Body.String())
	}
	orch.WaitBackground()
	whMu.Lock()
	whSigValid = false
	whIP = ""
	whMu.Unlock()
	wRecDrain := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/dns-failover/%d/reconcile", whGroup.ID), adminTok, nil, "")
	whMu.Lock()
	sig2, ip2 := whSigValid, whIP
	whMu.Unlock()
	if wRecDrain.Code != http.StatusOK || !sig2 || ip2 != "203.0.113.20" {
		t.Fatalf("maintenance drain reconcile failed: code=%d sigValid=%v ip=%q body=%s", wRecDrain.Code, sig2, ip2, wRecDrain.Body.String())
	}
}

// 6. Security Regression: Non-Admin Topology Scrubbing, Multi-Hop Node Quota Cutoff & Toggle Guard, and Failover RecordID Reset
func TestNextGenTopologyScrubbingNodeQuotaAndFailoverRecordReset(t *testing.T) {
	r, db, orch, _, _, cleanup := setupNextGenEnv(t)
	defer cleanup()
	defer orch.WaitBackground()

	adminTok := login(t, r, "admin@nexus.local", "admin123")
	userTok := login(t, r, "user@nexus.local", "user12345")

	mkNode := func(name, ip string, quota int64) model.Node {
		w := doJSON(r, http.MethodPost, "/api/v1/admin/nodes", adminTok, map[string]any{
			"name":        name,
			"connect_ip":  ip,
			"server_ip":   ip,
			"port_range":  "20000-30000",
			"quota_bytes": quota,
		}, "")
		if w.Code != http.StatusCreated {
			t.Fatalf("create node %s: %d %s", name, w.Code, w.Body.String())
		}
		var n model.Node
		_ = json.Unmarshal(w.Body.Bytes(), &n)
		return n
	}
	nIn := mkNode("Sec-In", "203.0.113.51", 100_000_000)
	nHop := mkNode("Sec-Hop", "203.0.113.52", 1_000) // tiny 1000-byte monthly quota on Hop!
	nEg := mkNode("Sec-Eg", "203.0.113.53", 100_000_000)

	wLine := doJSON(r, http.MethodPost, "/api/v1/admin/lines", adminTok, map[string]any{
		"name":            "Sec-MultiHop-Line",
		"type":            "encrypt",
		"ingress_node_id": nIn.ID,
		"hop_node_ids":    fmt.Sprintf("%d", nHop.ID),
		"egress_node_ids": fmt.Sprintf("%d:100", nEg.ID),
		"port_range":      "21000-22000",
		"enabled":         true,
	}, "")
	if wLine.Code != http.StatusCreated {
		t.Fatalf("create line failed: %d %s", wLine.Code, wLine.Body.String())
	}
	var line model.TunnelLine
	_ = json.Unmarshal(wLine.Body.Bytes(), &line)
	db.Model(&model.User{}).Where("email = ?", "user@nexus.local").Update("allowed_tunnels", fmt.Sprintf("1,2,%d", line.ID))

	// Non-admin GET /api/v1/lines must NOT expose hop_node_ids, egress_node_ids, or egress_node_id!
	wLines := doJSON(r, http.MethodGet, "/api/v1/lines", userTok, nil, "")
	var tenantLines []model.TunnelLine
	_ = json.Unmarshal(wLines.Body.Bytes(), &tenantLines)
	for _, tl := range tenantLines {
		if tl.ID == line.ID && (tl.HopNodeIDs != "" || tl.EgressNodeIDs != "" || tl.EgressNodeID != 0) {
			t.Fatalf("SECURITY FAILURE: tenant line leaked topology IDs: %+v", tl)
		}
	}

	// Tenant creates a rule on the multi-hop line -> response and GET /rules must scrub hop_ports_json, egress_ports_json, relay_port!
	wCreate := doJSON(r, http.MethodPost, "/api/v1/rules", userTok, map[string]any{
		"name":           "Tenant-Sec-Rule",
		"tunnel_line_id": line.ID,
		"protocol":       "tcp",
		"targets":        []map[string]any{{"address": "1.1.1.1:443"}},
	}, "")
	if wCreate.Code != http.StatusCreated {
		t.Fatalf("tenant create rule failed: %d %s", wCreate.Code, wCreate.Body.String())
	}
	var tenantRule model.ForwardRule
	_ = json.Unmarshal(wCreate.Body.Bytes(), &tenantRule)
	if tenantRule.HopPortsJSON != "" || tenantRule.EgressPortsJSON != "" || tenantRule.RelayPort != 0 {
		t.Fatalf("SECURITY FAILURE: create rule leaked internal relay ports to tenant: %+v", tenantRule)
	}
	wList := doJSON(r, http.MethodGet, "/api/v1/rules", userTok, nil, "")
	if strings.Contains(wList.Body.String(), "hop_ports_json") || strings.Contains(wList.Body.String(), "egress_ports_json") {
		t.Fatalf("SECURITY FAILURE: list rules leaked hop/egress port JSON: %s", wList.Body.String())
	}

	// Hop node exhausts its monthly quota via traffic report -> rule MUST be cut off as node_quota_exceeded!
	orch.HandleTrafficReport(nHop.ID, protocol.TrafficReportPayload{
		Timestamp: time.Now().Unix(),
		Deltas: []protocol.RuleTrafficDelta{
			{RuleID: tenantRule.ID, Role: protocol.RoleHop(0), UploadBytes: 800, DownBytes: 800},
		},
	})
	var dbRule model.ForwardRule
	db.First(&dbRule, tenantRule.ID)
	if dbRule.Enabled || dbRule.Status != "node_quota_exceeded" {
		t.Fatalf("expected multi-hop rule cut off with node_quota_exceeded when Hop exhausted quota, got enabled=%v status=%s", dbRule.Enabled, dbRule.Status)
	}

	// Tenant must NOT be able to bypass node_quota_exceeded via POST /api/v1/rules/:id/toggle or POST /api/v1/rules!
	wToggleBypass := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/rules/%d/toggle", tenantRule.ID), userTok, nil, "")
	if wToggleBypass.Code != http.StatusForbidden {
		t.Fatalf("SECURITY FAILURE: tenant bypassed node_quota_exceeded via toggle (%d): %s", wToggleBypass.Code, wToggleBypass.Body.String())
	}
	wCreateBypass := doJSON(r, http.MethodPost, "/api/v1/rules", userTok, map[string]any{
		"name":           "Bypass-Attempt",
		"tunnel_line_id": line.ID,
		"protocol":       "tcp",
		"targets":        []map[string]any{{"address": "1.1.1.1:443"}},
	}, "")
	if wCreateBypass.Code != http.StatusForbidden {
		t.Fatalf("SECURITY FAILURE: tenant created rule on over-quota Hop node (%d): %s", wCreateBypass.Code, wCreateBypass.Body.String())
	}

	// Admin resets Hop node traffic -> rule auto-resumes!
	wResetHop := doJSON(r, http.MethodPost, fmt.Sprintf("/api/v1/admin/nodes/%d/reset-traffic", nHop.ID), adminTok, nil, "")
	if wResetHop.Code != http.StatusOK {
		t.Fatalf("reset hop traffic failed: %d %s", wResetHop.Code, wResetHop.Body.String())
	}
	db.First(&dbRule, tenantRule.ID)
	if !dbRule.Enabled || (dbRule.Status != "running" && dbRule.Status != "syncing") {
		t.Fatalf("expected rule auto-resumed after Hop traffic reset, got enabled=%v status=%s", dbRule.Enabled, dbRule.Status)
	}

	// DNS Failover: malformed ZoneID rejected at API time; updating Domain clears stale cached RecordID!
	wBadZone := doJSON(r, http.MethodPost, "/api/v1/admin/dns-failover", adminTok, map[string]any{
		"name":            "Bad-Zone",
		"domain":          "a.example.com",
		"record_type":     "A",
		"primary_node_id": nIn.ID,
		"backup_node_ids": fmt.Sprintf("%d", nEg.ID),
		"provider":        "cloudflare",
		"zone_id":         "../../evil",
		"api_token":       "tok",
	}, "")
	if wBadZone.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unsafe zone_id, got %d", wBadZone.Code)
	}

	wGoodFG := doJSON(r, http.MethodPost, "/api/v1/admin/dns-failover", adminTok, map[string]any{
		"name":            "Domain-Change-Guard",
		"domain":          "old.example.com",
		"record_type":     "A",
		"primary_node_id": nIn.ID,
		"backup_node_ids": fmt.Sprintf("%d", nEg.ID),
		"provider":        "cloudflare",
		"zone_id":         "zone_valid_01",
		"record_id":       "rec_old_domain_111",
		"api_token":       "tok",
	}, "")
	if wGoodFG.Code != http.StatusCreated {
		t.Fatalf("create good failover group failed: %d %s", wGoodFG.Code, wGoodFG.Body.String())
	}
	var fg model.IngressFailoverGroup
	_ = json.Unmarshal(wGoodFG.Body.Bytes(), &fg)

	// Simulate UI echoing old record_id while changing domain -> backend MUST clear stale record_id!
	wUpdFG := doJSON(r, http.MethodPut, fmt.Sprintf("/api/v1/admin/dns-failover/%d", fg.ID), adminTok, map[string]any{
		"domain":    "new.example.com",
		"record_id": "rec_old_domain_111",
	}, "")
	if wUpdFG.Code != http.StatusOK {
		t.Fatalf("update failover group failed: %d %s", wUpdFG.Code, wUpdFG.Body.String())
	}
	db.First(&fg, fg.ID)
	if fg.RecordID != "" {
		t.Fatalf("expected stale RecordID cleared on domain change, got %q", fg.RecordID)
	}

	// DNSPod with explicit root domain ZoneID (e.g. multi-part TLD example.com.cn) + SubDomain must be accepted!
	wDPRoot := doJSON(r, http.MethodPost, "/api/v1/admin/dns-failover", adminTok, map[string]any{
		"name":            "DNSPod-CN-Root",
		"domain":          "hk-entry.example.com.cn",
		"record_type":     "A",
		"primary_node_id": nIn.ID,
		"backup_node_ids": fmt.Sprintf("%d", nEg.ID),
		"provider":        "dnspod",
		"zone_id":         "example.com.cn",
		"sub_domain":      "hk-entry",
		"api_token":       "10086,dp_tok",
	}, "")
	if wDPRoot.Code != http.StatusCreated {
		t.Fatalf("expected 201 for DNSPod explicit root domain zone_id, got %d: %s", wDPRoot.Code, wDPRoot.Body.String())
	}
}
