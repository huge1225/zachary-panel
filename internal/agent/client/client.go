package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"nexus-panel/internal/agent/engine"
	"nexus-panel/internal/agent/monitor"
	"nexus-panel/pkg/protocol"
)

const AgentVersion = "1.1.0-sec"

// Config holds security, synchronization interval, and connection parameters for the AgentClient.
type Config struct {
	MasterURL        string
	NodeID           uint64
	SecretToken      string
	MasterPinSHA256  string // Optional SHA-256 hex fingerprint of Master TLS certificate
	AllowPrivateSSRF bool
	ReportInterval   time.Duration // Probe & traffic delta sync frequency (default 3s)
}

// AgentClient maintains the persistent, HMAC-signed WebSocket connection to the Master server,
// verifies every Master instruction against tampering/replay, and reports heartbeats & traffic deltas.
type AgentClient struct {
	cfg         Config
	engMgr      *engine.Manager
	replayGuard *protocol.ReplayGuard
	writeMu     sync.Mutex
	conn        *websocket.Conn
}

func NewAgentClient(cfg Config, engMgr *engine.Manager) *AgentClient {
	return &AgentClient{
		cfg:         cfg,
		engMgr:      engMgr,
		replayGuard: protocol.NewReplayGuard(),
	}
}

// Run loops indefinitely, reconnecting with backoff whenever the connection drops.
func (c *AgentClient) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := c.connectAndServe(ctx); err != nil {
			log.Printf("[AgentClient] Disconnected from Master (%v), retrying in 5s...", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (c *AgentClient) connectAndServe(ctx context.Context) error {
	// Zero plaintext secrets in URL: authenticate via HMAC-SHA256 signed HTTP headers
	ts := time.Now().Unix()
	nonce := protocol.GenerateNonce()
	sig := protocol.ComputeHandshakeAuth(c.cfg.NodeID, ts, nonce, c.cfg.SecretToken)

	headers := http.Header{}
	headers.Set("X-Node-ID", fmt.Sprintf("%d", c.cfg.NodeID))
	headers.Set("X-Auth-Timestamp", fmt.Sprintf("%d", ts))
	headers.Set("X-Auth-Nonce", nonce)
	headers.Set("X-Auth-Signature", sig)

	dialer := *websocket.DefaultDialer
	if c.cfg.MasterPinSHA256 != "" {
		expectedPin := strings.ToLower(strings.TrimSpace(c.cfg.MasterPinSHA256))
		dialer.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("no server TLS certificate presented")
				}
				sum := sha256.Sum256(rawCerts[0])
				actualPin := hex.EncodeToString(sum[:])
				if actualPin != expectedPin {
					return fmt.Errorf("TLS certificate pin mismatch: got %s, expected %s", actualPin, expectedPin)
				}
				return nil
			},
		}
	}

	conn, _, err := dialer.DialContext(ctx, c.cfg.MasterURL, headers)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Enforce 4MB max message size to prevent memory exhaustion DoS
	conn.SetReadLimit(4 * 1024 * 1024)

	c.writeMu.Lock()
	c.conn = conn
	c.writeMu.Unlock()

	log.Printf("[AgentClient] Authenticated with Master %s (NodeID=%d, HMAC+AntiReplay=ON, Engines=%v)",
		c.cfg.MasterURL, c.cfg.NodeID, c.engMgr.SupportedEngines())

	// 1. Send signed registration payload (Master requires this as the very first frame). It also carries this
	// node's tunnel certificate so Master can pin it on Ingress nodes that connect to us.
	if err := c.sendEnvelope(protocol.MsgAgentRegister, protocol.AgentRegisterPayload{
		NodeID:           c.cfg.NodeID,
		AgentVersion:     AgentVersion,
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		SupportedEngines: c.engMgr.SupportedEngines(),
		TunnelCertPEM:    c.engMgr.TunnelCertPEM(),
	}); err != nil {
		return err
	}

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 2. Start background reporter loop for heartbeat & traffic deltas
	go c.reportLoop(connCtx)

	// 3. Read and cryptographically verify incoming Master instructions
	for {
		_, rawMsg, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		c.handleMessage(ctx, rawMsg)
	}
}

func (c *AgentClient) reportLoop(ctx context.Context) {
	interval := c.cfg.ReportInterval
	if interval < time.Second {
		interval = 3 * time.Second
	}
	intervalSec := uint64(interval.Seconds())
	if intervalSec == 0 {
		intervalSec = 3
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deltas, activeRules, activeConns := c.engMgr.CollectAllDeltas()

			var windowUp, windowDown int64
			for _, d := range deltas {
				windowUp += d.UploadBytes
				windowDown += d.DownBytes
			}

			metrics := monitor.CollectMetrics()
			_ = c.sendEnvelope(protocol.MsgAgentHeartbeat, protocol.AgentHeartbeatPayload{
				NodeID:           c.cfg.NodeID,
				CPUCores:         metrics.CPUCores,
				CPUUsagePercent:  metrics.CPUUsagePercent,
				Load1:            metrics.Load1,
				Load5:            metrics.Load5,
				Load15:           metrics.Load15,
				MemUsedBytes:     metrics.MemUsedBytes,
				MemTotalBytes:    metrics.MemTotalBytes,
				MemUsagePercent:  metrics.MemUsagePercent,
				DiskUsedBytes:    metrics.DiskUsedBytes,
				DiskTotalBytes:   metrics.DiskTotalBytes,
				DiskUsagePercent: metrics.DiskUsagePercent,
				NetRxBytesPerS:   uint64(windowDown) / intervalSec,
				NetTxBytesPerS:   uint64(windowUp) / intervalSec,
				ActiveRules:      activeRules,
				ActiveConns:      activeConns,
				SupportedEngines: c.engMgr.SupportedEngines(),
				UptimeSeconds:    metrics.UptimeSeconds,
			})

			if len(deltas) > 0 {
				_ = c.sendEnvelope(protocol.MsgTrafficReport, protocol.TrafficReportPayload{
					NodeID:    c.cfg.NodeID,
					Timestamp: time.Now().Unix(),
					Deltas:    deltas,
				})
			}
		}
	}
}

func (c *AgentClient) handleMessage(ctx context.Context, raw []byte) {
	// Verify HMAC-SHA256 signature, timestamp skew (±60s), and anti-replay nonce
	env, payloadBytes, err := protocol.VerifyEnvelope(raw, c.cfg.SecretToken, c.replayGuard)
	if err != nil {
		log.Printf("[AgentClient] SECURITY ALERT — Dropped invalid/tampered Master frame: %v", err)
		return
	}

	switch env.Type {
	case protocol.MsgSyncAllRules:
		var p protocol.SyncAllRulesPayload
		if err := json.Unmarshal(payloadBytes, &p); err == nil {
			acks := c.engMgr.SyncAll(ctx, p.Rules, p.ForceRestart)
			for _, ack := range acks {
				_ = c.sendEnvelope(protocol.MsgRuleStatusAck, ack)
			}
		}

	case protocol.MsgApplyRule:
		var spec protocol.RuleSpec
		if err := json.Unmarshal(payloadBytes, &spec); err == nil {
			err := c.engMgr.ApplyRule(ctx, spec)
			eng := c.engMgr.BoundEngine(spec.RuleID, spec.Role)
			if eng == "" {
				eng = spec.Engine
			}
			ack := protocol.RuleStatusAckPayload{
				RuleID:  spec.RuleID,
				Role:    spec.Role,
				Engine:  eng,
				Success: err == nil,
			}
			if err != nil {
				ack.Error = err.Error()
			}
			_ = c.sendEnvelope(protocol.MsgRuleStatusAck, ack)
		}

	case protocol.MsgRemoveRule:
		var p protocol.RemoveRulePayload
		if err := json.Unmarshal(payloadBytes, &p); err == nil {
			_ = c.engMgr.RemoveRule(p.RuleID, p.Role)
		}

	case protocol.MsgProbeTask:
		var p protocol.ProbeTaskPayload
		if err := json.Unmarshal(payloadBytes, &p); err == nil {
			go func() {
				latencies := monitor.ProbeTargets(p.Targets, c.cfg.AllowPrivateSSRF)
				_ = c.sendEnvelope(protocol.MsgProbeResult, protocol.ProbeResultPayload{
					NodeID:    c.cfg.NodeID,
					RuleID:    p.RuleID,
					Latencies: latencies,
				})
			}()
		}
	}
}

func (c *AgentClient) sendEnvelope(msgType protocol.MessageType, payload any) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("not connected")
	}
	env, err := protocol.SignEnvelope(msgType, payload, c.cfg.SecretToken)
	if err != nil {
		return err
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.conn.WriteJSON(env)
}
