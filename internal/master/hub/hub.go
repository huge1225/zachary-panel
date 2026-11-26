package hub

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
	"nexus-panel/internal/agent/security"
	"nexus-panel/internal/master/model"
	"nexus-panel/pkg/protocol"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  16384,
	WriteBufferSize: 16384,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// TrafficHandlerFunc is a callback invoked whenever an Agent reports incremental rule traffic.
type TrafficHandlerFunc func(nodeID uint64, report protocol.TrafficReportPayload)

// SyncNodeCallback is invoked right after an Agent connects and registers so Master pushes its rules.
type SyncNodeCallback func(nodeID uint64)

// AckScopeFunc reports whether a node is allowed to report status for (ruleID, role).
type AckScopeFunc func(nodeID uint64, ruleID uint64, role protocol.RuleRole) bool

const (
	// registerTimeout bounds how long a freshly upgraded connection may wait before sending its signed register frame.
	registerTimeout = 10 * time.Second
	// agentReadTimeout bounds idle silence on an established Agent WebSocket (Agents report every ~3s).
	agentReadTimeout = 90 * time.Second
)

// AgentSession represents a live connected Agent node.
type AgentSession struct {
	NodeID           uint64
	SecretToken      string
	ReplayGuard      *protocol.ReplayGuard
	ReportLimiter    *rate.Limiter
	Conn             *websocket.Conn
	WriteMu          sync.Mutex
	AgentVersion     string
	SupportedEngines []protocol.EngineType
	CPUCores         int
	CPUUsage         float64
	Load1            float64
	Load5            float64
	Load15           float64
	MemUsedBytes     uint64
	MemTotalBytes    uint64
	MemUsage         float64
	DiskUsedBytes    uint64
	DiskTotalBytes   uint64
	DiskUsage        float64
	NetRxBytesPerS   uint64
	NetTxBytesPerS   uint64
	ActiveRules      int
	ActiveConns      int64
	UptimeSeconds    int64
	ConnectedAt      time.Time
	LastHeartbeat    time.Time
}

func (s *AgentSession) Send(msgType protocol.MessageType, payload any) error {
	s.WriteMu.Lock()
	defer s.WriteMu.Unlock()

	env, err := protocol.SignEnvelope(msgType, payload, s.SecretToken)
	if err != nil {
		return err
	}
	_ = s.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return s.Conn.WriteJSON(env)
}

// AgentHub manages all connected Agent WebSocket sessions and probe callbacks.
type AgentHub struct {
	db             *gorm.DB
	mu             sync.RWMutex
	sessions       map[uint64]*AgentSession
	probeWaitersMu sync.Mutex
	probeWaiters   map[string]chan protocol.ProbeResultPayload // "nodeID:ruleID" -> channel
	onTraffic      TrafficHandlerFunc
	onNodeOnline   SyncNodeCallback
	onNodeOffline  SyncNodeCallback
	onCertChanged  SyncNodeCallback
	ackScope       AckScopeFunc

	guardsMu   sync.Mutex
	nodeGuards map[uint64]*protocol.ReplayGuard // per-node nonce cache shared across sessions (handshake + frames)

	wsFailMu     sync.Mutex
	wsFailByIP   map[string]*wsIPFailEntry
	wsFailLastGC time.Time
}

type wsIPFailEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

func NewAgentHub(db *gorm.DB) *AgentHub {
	return &AgentHub{
		db:           db,
		sessions:     make(map[uint64]*AgentSession),
		probeWaiters: make(map[string]chan protocol.ProbeResultPayload),
		nodeGuards:   make(map[uint64]*protocol.ReplayGuard),
		wsFailByIP:   make(map[string]*wsIPFailEntry),
	}
}

func (h *AgentHub) allowHandshakeFail(ip string) bool {
	h.wsFailMu.Lock()
	defer h.wsFailMu.Unlock()
	now := time.Now()
	if now.Sub(h.wsFailLastGC) > time.Minute || len(h.wsFailByIP) > 20000 {
		for k, e := range h.wsFailByIP {
			if now.Sub(e.lastSeen) > 10*time.Minute {
				delete(h.wsFailByIP, k)
			}
		}
		h.wsFailLastGC = now
	}
	e, ok := h.wsFailByIP[ip]
	if !ok {
		if len(h.wsFailByIP) >= 50000 {
			return false
		}
		e = &wsIPFailEntry{lim: rate.NewLimiter(rate.Every(3*time.Second), 8)}
		h.wsFailByIP[ip] = e
	}
	e.lastSeen = now
	return e.lim.Allow()
}

func (h *AgentHub) isHandshakeBlocked(ip string) bool {
	h.wsFailMu.Lock()
	defer h.wsFailMu.Unlock()
	e, ok := h.wsFailByIP[ip]
	if !ok {
		return false
	}
	return e.lim.Tokens() < 1.0 && time.Since(e.lastSeen) < 3*time.Second
}

func (h *AgentHub) SetCallbacks(onTraffic TrafficHandlerFunc, onNodeOnline SyncNodeCallback) {
	h.onTraffic = onTraffic
	h.onNodeOnline = onNodeOnline
}

// SetOfflineCallback registers a callback fired when a connected Agent disconnects.
func (h *AgentHub) SetOfflineCallback(cb SyncNodeCallback) {
	h.onNodeOffline = cb
}

// SetCertChangedCallback registers a callback fired when an Agent reports a new tunnel certificate.
func (h *AgentHub) SetCertChangedCallback(cb SyncNodeCallback) {
	h.onCertChanged = cb
}

// SetAckScope registers the authorization check applied to rule status acknowledgements.
func (h *AgentHub) SetAckScope(fn AckScopeFunc) {
	h.ackScope = fn
}

func (h *AgentHub) guardFor(nodeID uint64) *protocol.ReplayGuard {
	h.guardsMu.Lock()
	defer h.guardsMu.Unlock()
	g, ok := h.nodeGuards[nodeID]
	if !ok {
		g = protocol.NewReplayGuard()
		h.nodeGuards[nodeID] = g
	}
	return g
}

// HandleAgentWS upgrades HTTP connections from Agents and processes incoming frames.
func (h *AgentHub) HandleAgentWS(c *gin.Context) {
	clientIP := c.ClientIP()
	if h.isHandshakeBlocked(clientIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many failed agent handshakes"})
		return
	}
	rejectHandshake := func() {
		if !h.allowHandshakeFail(clientIP) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many failed agent handshakes"})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}

	nodeID, err := strconv.ParseUint(c.GetHeader("X-Node-ID"), 10, 64)
	if err != nil || nodeID == 0 {
		rejectHandshake()
		return
	}

	var node model.Node
	if err := h.db.First(&node, nodeID).Error; err != nil {
		rejectHandshake()
		return
	}

	// Enforce mandatory HMAC-SHA256 challenge headers (rejects plaintext/downgraded handshakes)
	authSig := c.GetHeader("X-Auth-Signature")
	authTS, _ := strconv.ParseInt(c.GetHeader("X-Auth-Timestamp"), 10, 64)
	authNonce := c.GetHeader("X-Auth-Nonce")

	if err := protocol.VerifyHandshakeAuth(nodeID, authTS, authNonce, authSig, node.SecretToken); err != nil {
		log.Printf("[AgentHub] Rejected handshake for node #%d from %s: %v", nodeID, clientIP, err)
		rejectHandshake()
		return
	}
	// Global (cross-session) replay protection for the handshake itself.
	replayGuard := h.guardFor(nodeID)
	if !replayGuard.Accept("hs:"+authNonce, authTS) {
		log.Printf("[AgentHub] Rejected replayed handshake for node #%d from %s", nodeID, clientIP)
		rejectHandshake()
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(4 * 1024 * 1024)
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(agentReadTimeout))
		return nil
	})

	sess := &AgentSession{
		NodeID:        nodeID,
		SecretToken:   node.SecretToken,
		ReplayGuard:   replayGuard,
		ReportLimiter: rate.NewLimiter(rate.Every(time.Second), 6),
		Conn:          conn,
		ConnectedAt:   time.Now(),
		LastHeartbeat: time.Now(),
	}

	// The new connection only replaces an existing session after it proves possession of the node token with a
	// fresh, signed register frame. This prevents a replayed/forged upgrade from kicking the real Agent offline.
	_ = conn.SetReadDeadline(time.Now().Add(registerTimeout))
	_, first, err := conn.ReadMessage()
	if err != nil {
		_ = conn.Close()
		return
	}
	env, firstPayload, err := protocol.VerifyEnvelope(first, sess.SecretToken, sess.ReplayGuard)
	if err != nil || env.Type != protocol.MsgAgentRegister {
		log.Printf("[AgentHub] Node #%d did not send a valid register frame; closing", nodeID)
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(agentReadTimeout))

	h.mu.Lock()
	if prev, ok := h.sessions[nodeID]; ok {
		_ = prev.Conn.Close()
	}
	h.sessions[nodeID] = sess
	h.mu.Unlock()

	log.Printf("[AgentHub] Node #%d (%s) connected", node.ID, node.Name)

	defer func() {
		_ = conn.Close()
		disconnected := false
		h.mu.Lock()
		if cur, ok := h.sessions[nodeID]; ok && cur == sess {
			delete(h.sessions, nodeID)
			h.db.Model(&model.Node{}).Where("id = ?", nodeID).Update("status", "offline")
			log.Printf("[AgentHub] Node #%d (%s) disconnected", node.ID, node.Name)
			disconnected = true
		}
		h.mu.Unlock()
		if disconnected && h.onNodeOffline != nil {
			go h.onNodeOffline(nodeID)
		}
	}()

	h.handleRegister(sess, firstPayload)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(agentReadTimeout))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		h.processAgentMessage(sess, raw)
	}
}

func sanitizeVersionString(v string) string {
	v = strings.TrimSpace(v)
	var b strings.Builder
	for _, r := range v {
		if r >= 0x20 && r != 0x7f && b.Len() < 32 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sanitizeFloat(v, minVal, maxVal float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < minVal {
		return minVal
	}
	if v > maxVal {
		return maxVal
	}
	return v
}

func (h *AgentHub) handleRegister(sess *AgentSession, payloadBytes []byte) {
	var reg protocol.AgentRegisterPayload
	if err := json.Unmarshal(payloadBytes, &reg); err != nil {
		return
	}
	var engStrs []string
	var cleanEngines []protocol.EngineType
	for _, e := range reg.SupportedEngines {
		switch e {
		case protocol.EngineNative, protocol.EngineGost, protocol.EngineRealm, protocol.EngineNftables:
			engStrs = append(engStrs, string(e))
			cleanEngines = append(cleanEngines, e)
		}
	}
	ver := sanitizeVersionString(reg.AgentVersion)
	h.mu.Lock()
	sess.SupportedEngines = cleanEngines
	if ver != "" {
		sess.AgentVersion = ver
	}
	h.mu.Unlock()

	now := time.Now()
	updates := map[string]any{
		"supported_engines": strings.Join(engStrs, ","),
		"status":            "online",
		"last_seen_at":      &now,
	}
	if ver != "" {
		updates["agent_version"] = ver
	}
	certChanged := false
	if reg.TunnelCertPEM != "" {
		if err := security.ValidateTunnelCertPEM(reg.TunnelCertPEM); err != nil {
			log.Printf("[AgentHub] Node #%d reported an invalid tunnel certificate: %v", sess.NodeID, err)
		} else {
			var cur model.Node
			if err := h.db.Select("id, tunnel_cert_pem").First(&cur, sess.NodeID).Error; err == nil && cur.TunnelCertPEM != reg.TunnelCertPEM {
				updates["tunnel_cert_pem"] = reg.TunnelCertPEM
				certChanged = true
			}
		}
	}
	h.db.Model(&model.Node{}).Where("id = ?", sess.NodeID).Updates(updates)
	if h.onNodeOnline != nil {
		go h.onNodeOnline(sess.NodeID)
	}
	if certChanged && h.onCertChanged != nil {
		// Ingress nodes pinning this egress must receive the new certificate.
		go h.onCertChanged(sess.NodeID)
	}
}

func (h *AgentHub) processAgentMessage(sess *AgentSession, raw []byte) {
	env, payloadBytes, err := protocol.VerifyEnvelope(raw, sess.SecretToken, sess.ReplayGuard)
	if err != nil {
		log.Printf("[AgentHub] Dropped unverified/replayed frame from Node #%d: %v", sess.NodeID, err)
		return
	}

	switch env.Type {
	case protocol.MsgAgentRegister:
		h.handleRegister(sess, payloadBytes)

	case protocol.MsgAgentHeartbeat:
		var hb protocol.AgentHeartbeatPayload
		if err := json.Unmarshal(payloadBytes, &hb); err == nil {
			ver := sanitizeVersionString(hb.AgentVersion)
			cores := hb.CPUCores
			if cores < 0 || cores > 4096 {
				cores = 0
			}
			activeRules := hb.ActiveRules
			if activeRules < 0 || activeRules > 100000 {
				activeRules = 0
			}
			activeConns := hb.ActiveConns
			if activeConns < 0 || activeConns > 100000000 {
				activeConns = 0
			}
			uptime := hb.UptimeSeconds
			if uptime < 0 {
				uptime = 0
			}
			h.mu.Lock()
			if ver != "" {
				sess.AgentVersion = ver
			}
			sess.CPUCores = cores
			sess.CPUUsage = sanitizeFloat(hb.CPUUsagePercent, 0, 100)
			sess.Load1 = sanitizeFloat(hb.Load1, 0, 100000)
			sess.Load5 = sanitizeFloat(hb.Load5, 0, 100000)
			sess.Load15 = sanitizeFloat(hb.Load15, 0, 100000)
			sess.MemUsedBytes = hb.MemUsedBytes
			sess.MemTotalBytes = hb.MemTotalBytes
			sess.MemUsage = sanitizeFloat(hb.MemUsagePercent, 0, 100)
			sess.DiskUsedBytes = hb.DiskUsedBytes
			sess.DiskTotalBytes = hb.DiskTotalBytes
			sess.DiskUsage = sanitizeFloat(hb.DiskUsagePercent, 0, 100)
			sess.NetRxBytesPerS = hb.NetRxBytesPerS
			sess.NetTxBytesPerS = hb.NetTxBytesPerS
			sess.ActiveRules = activeRules
			sess.ActiveConns = activeConns
			sess.UptimeSeconds = uptime
			sess.LastHeartbeat = time.Now()
			if len(hb.SupportedEngines) > 0 && len(hb.SupportedEngines) <= 8 {
				var clean []protocol.EngineType
				for _, e := range hb.SupportedEngines {
					switch e {
					case protocol.EngineNative, protocol.EngineGost, protocol.EngineRealm, protocol.EngineNftables:
						clean = append(clean, e)
					}
				}
				if len(clean) > 0 {
					sess.SupportedEngines = clean
				}
			}
			h.mu.Unlock()

			now := time.Now()
			hbUpdates := map[string]any{
				"status":       "online",
				"last_seen_at": &now,
			}
			if ver != "" {
				hbUpdates["agent_version"] = ver
			}
			h.db.Model(&model.Node{}).Where("id = ?", sess.NodeID).Updates(hbUpdates)
		}

	case protocol.MsgTrafficReport:
		if sess.ReportLimiter != nil && !sess.ReportLimiter.Allow() {
			log.Printf("[AgentHub] Rate-limited excessive traffic report from Node #%d", sess.NodeID)
			return
		}
		var tr protocol.TrafficReportPayload
		if err := json.Unmarshal(payloadBytes, &tr); err == nil {
			if h.onTraffic != nil {
				h.onTraffic(sess.NodeID, tr)
			}
		}

	case protocol.MsgRuleStatusAck:
		var ack protocol.RuleStatusAckPayload
		if err := json.Unmarshal(payloadBytes, &ack); err == nil {
			// Only accept acknowledgements for rules this node actually hosts in the reported role.
			if h.ackScope == nil || !h.ackScope(sess.NodeID, ack.RuleID, ack.Role) {
				log.Printf("[AgentHub] Dropped out-of-scope rule ack from Node #%d (rule #%d, role %q)", sess.NodeID, ack.RuleID, ack.Role)
				return
			}
			status := "running"
			lastErr := ""
			if !ack.Success {
				status = "error"
				lastErr = ack.Error
				lastErr = truncateUTF8(lastErr, 255)
			}
			// Never re-enable paused / quota-exceeded rules through an ack.
			h.db.Model(&model.ForwardRule{}).Where("id = ? AND enabled = ?", ack.RuleID, true).Updates(map[string]any{
				"status":     status,
				"last_error": lastErr,
			})
		}

	case protocol.MsgProbeResult:
		var res protocol.ProbeResultPayload
		if err := json.Unmarshal(payloadBytes, &res); err == nil {
			waitKey := fmt.Sprintf("%d:%d", sess.NodeID, res.RuleID)
			h.probeWaitersMu.Lock()
			if ch, ok := h.probeWaiters[waitKey]; ok {
				select {
				case ch <- res:
				default:
				}
			}
			h.probeWaitersMu.Unlock()
		}
	}
}

// EnrichNodeMetrics populates live in-memory metrics onto a Node struct for API responses.
func (h *AgentHub) EnrichNodeMetrics(n *model.Node) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if sess, ok := h.sessions[n.ID]; ok {
		n.Status = "online"
		if sess.AgentVersion != "" {
			n.AgentVersion = sess.AgentVersion
		}
		n.CPUCores = sess.CPUCores
		n.CPUUsage = sess.CPUUsage
		n.Load1 = sess.Load1
		n.Load5 = sess.Load5
		n.Load15 = sess.Load15
		n.MemUsedBytes = sess.MemUsedBytes
		n.MemTotalBytes = sess.MemTotalBytes
		n.MemUsage = sess.MemUsage
		n.DiskUsedBytes = sess.DiskUsedBytes
		n.DiskTotalBytes = sess.DiskTotalBytes
		n.DiskUsage = sess.DiskUsage
		n.NetRxBytesPerS = sess.NetRxBytesPerS
		n.NetTxBytesPerS = sess.NetTxBytesPerS
		n.ActiveRules = sess.ActiveRules
		n.ActiveConns = sess.ActiveConns
		n.UptimeSeconds = sess.UptimeSeconds
	} else if n.Status == "online" {
		n.Status = "offline"
	}
}

// OnlineNodeIDs returns the IDs of all currently connected Agent nodes.
func (h *AgentHub) OnlineNodeIDs() []uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ids := make([]uint64, 0, len(h.sessions))
	for id := range h.sessions {
		ids = append(ids, id)
	}
	return ids
}

// SendToNode sends a protocol message to a connected Agent if online.
func (h *AgentHub) SendToNode(nodeID uint64, msgType protocol.MessageType, payload any) error {
	h.mu.RLock()
	sess, ok := h.sessions[nodeID]
	h.mu.RUnlock()
	if !ok {
		return fmt.Errorf("node %d is offline", nodeID)
	}
	return sess.Send(msgType, payload)
}

// RequestProbe triggers a live TCP latency probe on the Agent and waits up to 4 seconds for results.
func (h *AgentHub) RequestProbe(nodeID uint64, ruleID uint64, targets []string) (map[string]int, error) {
	waitKey := fmt.Sprintf("%d:%d", nodeID, ruleID)
	ch := make(chan protocol.ProbeResultPayload, 1)
	h.probeWaitersMu.Lock()
	h.probeWaiters[waitKey] = ch
	h.probeWaitersMu.Unlock()

	defer func() {
		h.probeWaitersMu.Lock()
		if cur, ok := h.probeWaiters[waitKey]; ok && cur == ch {
			delete(h.probeWaiters, waitKey)
		}
		h.probeWaitersMu.Unlock()
	}()

	err := h.SendToNode(nodeID, protocol.MsgProbeTask, protocol.ProbeTaskPayload{
		RuleID:  ruleID,
		Targets: targets,
	})
	if err != nil {
		return nil, err
	}

	select {
	case res := <-ch:
		return res.Latencies, nil
	case <-time.After(4 * time.Second):
		return nil, fmt.Errorf("probe timed out waiting for agent response")
	}
}

// truncateUTF8 shortens s to at most max bytes without splitting a multi-byte character.
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
