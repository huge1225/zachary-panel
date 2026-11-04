package hub

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"gorm.io/gorm"
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

// AgentSession represents a live connected Agent node.
type AgentSession struct {
	NodeID           uint64
	SecretToken      string
	ReplayGuard      *protocol.ReplayGuard
	Conn             *websocket.Conn
	WriteMu          sync.Mutex
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
}

func NewAgentHub(db *gorm.DB) *AgentHub {
	return &AgentHub{
		db:           db,
		sessions:     make(map[uint64]*AgentSession),
		probeWaiters: make(map[string]chan protocol.ProbeResultPayload),
	}
}

func (h *AgentHub) SetCallbacks(onTraffic TrafficHandlerFunc, onNodeOnline SyncNodeCallback) {
	h.onTraffic = onTraffic
	h.onNodeOnline = onNodeOnline
}

// HandleAgentWS upgrades HTTP connections from Agents and processes incoming frames.
func (h *AgentHub) HandleAgentWS(c *gin.Context) {
	nodeIDStr := c.GetHeader("X-Node-ID")
	if nodeIDStr == "" {
		nodeIDStr = c.Query("node_id")
	}
	nodeID, err := strconv.ParseUint(nodeIDStr, 10, 64)
	if err != nil || nodeID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid node_id"})
		return
	}

	var node model.Node
	if err := h.db.First(&node, nodeID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "node not found"})
		return
	}

	// Enforce mandatory HMAC-SHA256 challenge headers (rejects plaintext/downgraded handshakes)
	authSig := c.GetHeader("X-Auth-Signature")
	authTS, _ := strconv.ParseInt(c.GetHeader("X-Auth-Timestamp"), 10, 64)
	authNonce := c.GetHeader("X-Auth-Nonce")

	replayGuard := protocol.NewReplayGuard()
	if err := protocol.VerifyHandshakeAuth(nodeID, authTS, authNonce, authSig, node.SecretToken); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	replayGuard.Accept(authNonce, authTS)

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(4 * 1024 * 1024)

	sess := &AgentSession{
		NodeID:        nodeID,
		SecretToken:   node.SecretToken,
		ReplayGuard:   replayGuard,
		Conn:          conn,
		ConnectedAt:   time.Now(),
		LastHeartbeat: time.Now(),
	}

	h.mu.Lock()
	if prev, ok := h.sessions[nodeID]; ok {
		_ = prev.Conn.Close()
	}
	h.sessions[nodeID] = sess
	h.mu.Unlock()

	now := time.Now()
	h.db.Model(&model.Node{}).Where("id = ?", nodeID).Updates(map[string]any{
		"status":       "online",
		"last_seen_at": &now,
	})

	log.Printf("[AgentHub] Node #%d (%s) connected", node.ID, node.Name)

	defer func() {
		_ = conn.Close()
		h.mu.Lock()
		if cur, ok := h.sessions[nodeID]; ok && cur == sess {
			delete(h.sessions, nodeID)
			h.db.Model(&model.Node{}).Where("id = ?", nodeID).Update("status", "offline")
			log.Printf("[AgentHub] Node #%d (%s) disconnected", node.ID, node.Name)
		}
		h.mu.Unlock()
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		h.processAgentMessage(sess, raw)
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
		var reg protocol.AgentRegisterPayload
		if err := json.Unmarshal(payloadBytes, &reg); err == nil {
			var engStrs []string
			for _, e := range reg.SupportedEngines {
				engStrs = append(engStrs, string(e))
			}
			sess.SupportedEngines = reg.SupportedEngines
			now := time.Now()
			h.db.Model(&model.Node{}).Where("id = ?", sess.NodeID).Updates(map[string]any{
				"supported_engines": strings.Join(engStrs, ","),
				"status":            "online",
				"last_seen_at":      &now,
			})
			if h.onNodeOnline != nil {
				go h.onNodeOnline(sess.NodeID)
			}
		}

	case protocol.MsgAgentHeartbeat:
		var hb protocol.AgentHeartbeatPayload
		if err := json.Unmarshal(payloadBytes, &hb); err == nil {
			h.mu.Lock()
			sess.CPUCores = hb.CPUCores
			sess.CPUUsage = hb.CPUUsagePercent
			sess.Load1 = hb.Load1
			sess.Load5 = hb.Load5
			sess.Load15 = hb.Load15
			sess.MemUsedBytes = hb.MemUsedBytes
			sess.MemTotalBytes = hb.MemTotalBytes
			sess.MemUsage = hb.MemUsagePercent
			sess.DiskUsedBytes = hb.DiskUsedBytes
			sess.DiskTotalBytes = hb.DiskTotalBytes
			sess.DiskUsage = hb.DiskUsagePercent
			sess.NetRxBytesPerS = hb.NetRxBytesPerS
			sess.NetTxBytesPerS = hb.NetTxBytesPerS
			sess.ActiveRules = hb.ActiveRules
			sess.ActiveConns = hb.ActiveConns
			sess.UptimeSeconds = hb.UptimeSeconds
			sess.LastHeartbeat = time.Now()
			if len(hb.SupportedEngines) > 0 {
				sess.SupportedEngines = hb.SupportedEngines
			}
			h.mu.Unlock()

			now := time.Now()
			h.db.Model(&model.Node{}).Where("id = ?", sess.NodeID).Updates(map[string]any{
				"status":       "online",
				"last_seen_at": &now,
			})
		}

	case protocol.MsgTrafficReport:
		var tr protocol.TrafficReportPayload
		if err := json.Unmarshal(payloadBytes, &tr); err == nil {
			if h.onTraffic != nil {
				h.onTraffic(sess.NodeID, tr)
			}
		}

	case protocol.MsgRuleStatusAck:
		var ack protocol.RuleStatusAckPayload
		if err := json.Unmarshal(payloadBytes, &ack); err == nil {
			status := "running"
			if !ack.Success {
				status = "error"
			}
			h.db.Model(&model.ForwardRule{}).Where("id = ?", ack.RuleID).Updates(map[string]any{
				"status":     status,
				"last_error": ack.Error,
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
		delete(h.probeWaiters, waitKey)
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
