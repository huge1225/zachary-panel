package client

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
	OnUpgrade        func(protocol.UpgradeAgentPayload)
}

// AgentClient maintains the persistent, HMAC-signed WebSocket connection to the Master server,
// verifies every Master instruction against tampering/replay, and reports heartbeats & traffic deltas.
type AgentClient struct {
	cfg         Config
	engMgr      *engine.Manager
	replayGuard *protocol.ReplayGuard
	writeMu     sync.Mutex
	conn        *websocket.Conn
	upgrading   atomic.Bool
}

func NewAgentClient(cfg Config, engMgr *engine.Manager) *AgentClient {
	return &AgentClient{
		cfg:         cfg,
		engMgr:      engMgr,
		replayGuard: protocol.NewReplayGuard(),
	}
}

func (c *AgentClient) tlsConfig() *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if c.cfg.MasterPinSHA256 != "" {
		expectedPin := strings.ToLower(strings.TrimSpace(c.cfg.MasterPinSHA256))
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no server TLS certificate presented")
			}
			sum := sha256.Sum256(rawCerts[0])
			actualPin := hex.EncodeToString(sum[:])
			if actualPin != expectedPin {
				return fmt.Errorf("TLS certificate pin mismatch: got %s, expected %s", actualPin, expectedPin)
			}
			return nil
		}
	}
	return cfg
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
	if strings.HasPrefix(strings.ToLower(c.cfg.MasterURL), "wss://") || c.cfg.MasterPinSHA256 != "" {
		dialer.TLSClientConfig = c.tlsConfig()
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

			var windowUp, windowDown uint64
			for _, d := range deltas {
				if d.UploadBytes > 0 {
					windowUp += uint64(d.UploadBytes)
				}
				if d.DownBytes > 0 {
					windowDown += uint64(d.DownBytes)
				}
			}

			metrics := monitor.CollectMetrics()
			_ = c.sendEnvelope(protocol.MsgAgentHeartbeat, protocol.AgentHeartbeatPayload{
				NodeID:           c.cfg.NodeID,
				AgentVersion:     AgentVersion,
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
				NetRxBytesPerS:   windowDown / intervalSec,
				NetTxBytesPerS:   windowUp / intervalSec,
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

	case protocol.MsgUpgradeAgent:
		var p protocol.UpgradeAgentPayload
		if err := json.Unmarshal(payloadBytes, &p); err == nil {
			if c.cfg.OnUpgrade != nil {
				c.cfg.OnUpgrade(p)
				return
			}
			go c.performSelfUpgrade(p)
		}
	}
}

func (c *AgentClient) performSelfUpgrade(p protocol.UpgradeAgentPayload) {
	if !c.upgrading.CompareAndSwap(false, true) {
		log.Printf("[AgentClient] Upgrade already in progress, ignoring duplicate instruction")
		return
	}
	defer c.upgrading.Store(false)

	arch := runtime.GOARCH
	expectedHash := strings.ToLower(strings.TrimSpace(p.SHA256ByArch[arch]))
	if len(expectedHash) != 64 {
		log.Printf("[AgentClient] Ignored upgrade instruction: missing 64-char SHA-256 for arch %s", arch)
		return
	}
	if _, err := hex.DecodeString(expectedHash); err != nil {
		log.Printf("[AgentClient] Ignored upgrade instruction: non-hex SHA-256 for arch %s", arch)
		return
	}

	baseURL := strings.TrimRight(strings.TrimSpace(p.BaseURL), "/")
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		log.Printf("[AgentClient] Ignored upgrade instruction: invalid base_url %q", baseURL)
		return
	}
	masterU, mErr := url.Parse(c.cfg.MasterURL)
	if mErr != nil || !strings.EqualFold(u.Hostname(), masterU.Hostname()) {
		log.Printf("[AgentClient] SECURITY ALERT — Rejected upgrade base_url host %q (does not match Master host %q)", u.Hostname(), masterU.Hostname())
		return
	}
	if strings.EqualFold(masterU.Scheme, "wss") && u.Scheme != "https" {
		log.Printf("[AgentClient] SECURITY ALERT — Rejected non-HTTPS upgrade base_url %q when Master uses wss://", baseURL)
		return
	}

	relPrefix := "/deploy/releases"
	if strings.HasSuffix(u.Path, "/deploy") {
		relPrefix = "/releases"
	}
	binURL := fmt.Sprintf("%s%s/nexus-agent-linux-%s", baseURL, relPrefix, arch)
	log.Printf("[AgentClient] Starting verified self-upgrade to %s from %s (sha256=%s)", p.TargetVersion, binURL, expectedHash)

	httpClient := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: c.tlsConfig(),
		},
	}
	resp, err := httpClient.Get(binURL)
	if err != nil {
		log.Printf("[AgentClient] Upgrade download failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[AgentClient] Upgrade download returned status %d", resp.StatusCode)
		return
	}

	exePath, err := os.Executable()
	if err != nil {
		log.Printf("[AgentClient] Cannot resolve executable path: %v", err)
		return
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(exePath), ".nexus-agent-upgrade-*")
	if err != nil {
		log.Printf("[AgentClient] Cannot create temp binary file: %v", err)
		return
	}
	tmpPath := tmpFile.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmpFile, hasher), io.LimitReader(resp.Body, 128*1024*1024)); err != nil {
		_ = tmpFile.Close()
		log.Printf("[AgentClient] Failed writing upgrade binary: %v", err)
		return
	}
	_ = tmpFile.Close()

	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if actualHash != expectedHash {
		log.Printf("[AgentClient] SECURITY ALERT — Upgrade binary SHA-256 mismatch: expected %s, got %s", expectedHash, actualHash)
		return
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		log.Printf("[AgentClient] Chmod upgrade binary failed: %v", err)
		return
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		log.Printf("[AgentClient] Atomic binary replacement failed: %v", err)
		return
	}
	log.Printf("[AgentClient] Binary upgraded to %s successfully; exiting for service manager restart", p.TargetVersion)
	os.Exit(0)
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
