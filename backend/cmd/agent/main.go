package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	grpcPkg "github.com/huge1225/zachary-panel/backend/internal/grpc"
	"github.com/huge1225/zachary-panel/backend/internal/manager"
)

func main() {
	panelAddr := envOrDefault("PANEL_ADDR", "panel.example.com:9090")
	agentID := envOrDefault("AGENT_ID", "")
	certDir := envOrDefault("CERT_DIR", "/etc/zachary-agent/certs")
	token := envOrDefault("AGENT_TOKEN", "")

	if agentID == "" {
		hostname, _ := os.Hostname()
		agentID = hostname
	}

	log.Printf("⚡ Zachary Panel Agent starting...")
	log.Printf("   Panel: %s", panelAddr)
	log.Printf("   AgentID: %s", agentID)
	log.Printf("   Certs: %s", certDir)

	caDir := certDir

	// 创建gRPC客户端连接到Panel
	client, err := grpcPkg.NewGRPCClient(panelAddr, certDir, caDir)
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}
	defer client.Close()

	// 注册Agent到Panel
	hostname, _ := os.Hostname()
	regResp, err := client.RegisterAgent(&grpcPkg.RegisterRequest{
		Id:       agentID,
		Hostname: hostname,
		Ip:       "127.0.0.1",
		Os:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Token:    token,
	})
	if err != nil {
		log.Fatalf("Failed to register agent: %v", err)
	}
	if !regResp.Success {
		log.Fatalf("Registration rejected: %s", regResp.Message)
	}
	log.Printf("✅ Agent registered: %s (%d rules)", agentID, len(regResp.Rules))

	// 创建配置管理器
	configMgr := manager.NewConfigManager()

	// 启动Agent gRPC服务端（接收Panel推送的配置）
	agent := grpcPkg.NewAgent()
	go func() {
		agentPort := envOrDefault("AGENT_GRPC_PORT", ":9091")
		log.Printf("Agent gRPC server on %s", agentPort)
		if err := grpcPkg.RunAgentServer(agentPort, certDir, caDir, agent); err != nil {
			log.Printf("Agent gRPC server error: %v", err)
		}
	}()

	// 应用注册时返回的规则
	if len(regResp.Rules) > 0 {
		if err := configMgr.ApplyConfig(regResp.Rules); err != nil {
			log.Printf("Failed to apply initial rules: %v", err)
		}
	}

	// 监听配置更新
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go configMgr.WatchConfigUpdates(ctx, agent)

	// 启动心跳
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				resp, err := client.Heartbeat(agentID)
				if err != nil {
					log.Printf("❌ Heartbeat failed: %v", err)
				} else if resp.Success {
					log.Printf("💓 Heartbeat OK")
				}
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutting down agent...")
	configMgr.StopAll()
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
