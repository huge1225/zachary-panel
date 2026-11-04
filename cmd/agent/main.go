package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"nexus-panel/internal/agent/client"
	"nexus-panel/internal/agent/engine"
	"nexus-panel/internal/agent/security"
)

func main() {
	var (
		masterURL       = flag.String("master", getEnv("NEXUS_MASTER_URL", "ws://127.0.0.1:8080/api/v1/agent/ws"), "Master WebSocket URL")
		nodeID          = flag.Uint64("id", getEnvUint64("NEXUS_NODE_ID", 1), "Node ID assigned by Master panel")
		token           = flag.String("token", getEnv("NEXUS_NODE_TOKEN", "dev-node-secret"), "Node communication secret token (HMAC key)")
		masterPinSHA256 = flag.String("master-pin-sha256", getEnv("NEXUS_MASTER_PIN_SHA256", ""), "Optional Master TLS certificate SHA-256 hex fingerprint")
		allowPrivateIPs = flag.Bool("allow-private-targets", getEnv("NEXUS_ALLOW_PRIVATE_TARGETS", "false") == "true", "Allow forwarding to RFC1918 private IPs (disabled by default for Anti-SSRF)")
		minListenPort   = flag.Int("min-port", 1024, "Minimum allowed local listen port")
		maxConnsPerIP   = flag.Int("max-conns-per-ip", 256, "Maximum concurrent connections per client IP")
		reportInterval  = flag.Duration("report-interval", 3*time.Second, "Heartbeat probe & traffic sync interval (default 3s)")
	)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	secPolicy := security.Policy{
		AllowPrivateTargets: *allowPrivateIPs,
		MinListenPort:       *minListenPort,
		MaxListenPort:       65535,
		MaxConnsPerClientIP: *maxConnsPerIP,
	}

	engMgr := engine.NewManager(secPolicy)
	defer func() {
		log.Println("[Agent] Shutting down forwarding engines...")
		_ = engMgr.Close()
	}()

	// Immediately restore and restart all active forwarding rules from local snapshot upon service boot/restart
	engMgr.RestoreSnapshot(ctx)

	log.Printf("[Agent] Starting Nexus Agent (NodeID=%d, SyncInterval=%s, Anti-SSRF=%v, Engines=%v)",
		*nodeID, *reportInterval, !*allowPrivateIPs, engMgr.SupportedEngines())

	agentCli := client.NewAgentClient(client.Config{
		MasterURL:        *masterURL,
		NodeID:           *nodeID,
		SecretToken:      *token,
		MasterPinSHA256:  *masterPinSHA256,
		AllowPrivateSSRF: *allowPrivateIPs,
		ReportInterval:   *reportInterval,
	}, engMgr)
	agentCli.Run(ctx)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvUint64(key string, fallback uint64) uint64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}
