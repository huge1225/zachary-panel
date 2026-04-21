package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/huge1225/zachary-panel/backend/internal/api"
	"github.com/huge1225/zachary-panel/backend/internal/cert"
	"github.com/huge1225/zachary-panel/backend/internal/db"
	"github.com/huge1225/zachary-panel/backend/internal/grpc"
)

func main() {
	dataDir := envOrDefault("DATA_DIR", "/data")
	listen := envOrDefault("LISTEN", ":8080")
	grpcAddr := envOrDefault("GRPC_ADDR", ":9090")

	// 初始化证书
	certDir := filepath.Join(dataDir, "certs")
	caDir := filepath.Join(certDir, "ca")
	serverDir := filepath.Join(certDir, "server")

	if _, err := os.Stat(filepath.Join(caDir, "ca.crt")); os.IsNotExist(err) {
		log.Println("Generating CA certificate...")
		if err := cert.GenerateCA(caDir); err != nil {
			log.Fatalf("Failed to generate CA: %v", err)
		}
		log.Println("Generating server certificate...")
		if err := cert.GenerateCert(caDir, serverDir, "zachary-panel-server"); err != nil {
			log.Fatalf("Failed to generate server cert: %v", err)
		}
	}

	// 初始化数据库
	dbPath := filepath.Join(dataDir, "panel.db")
	database, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()

	// 创建 gRPC Store 适配器
	grpcStore := &dbGrpcStore{db: database}

	// 启动 gRPC 服务
	go func() {
		if err := startGRPC(grpcAddr, serverDir, caDir, grpcStore); err != nil {
			log.Fatalf("gRPC server failed: %v", err)
		}
	}()

	// 启动 HTTP API
	srv := api.NewServer(database)
	log.Printf("⚡ Panel HTTP server on %s", listen)
	log.Printf("🔒 gRPC agent server on %s (mTLS)", grpcAddr)
	if err := srv.Run(listen); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

// dbGrpcStore 实现 grpc.AgentStore 接口
type dbGrpcStore struct {
	db *db.DB
}

func (s *dbGrpcStore) GetAgent(id string) (*grpc.AgentInfo, error) {
	a, err := s.db.GetAgent(id)
	if err != nil {
		return nil, err
	}
	return &grpc.AgentInfo{
		ID: a.ID, Hostname: a.Hostname, IP: a.IP,
		OS: a.OS, Arch: a.Arch, Status: a.Status,
		Token: a.Token, LastSeen: a.LastSeen, CreatedAt: a.CreatedAt,
	}, nil
}

func (s *dbGrpcStore) GetRulesByAgent(agentID string) ([]grpc.ForwardRuleInfo, error) {
	rules, err := s.db.GetRulesByAgent(agentID)
	if err != nil {
		return nil, err
	}
	result := make([]grpc.ForwardRuleInfo, len(rules))
	for i, r := range rules {
		result[i] = grpc.ForwardRuleInfo{
			ID: r.ID, AgentID: r.AgentID, ListenAddr: r.ListenAddr,
			TargetAddr: r.TargetAddr, Protocol: r.Protocol,
			Enabled: r.Enabled, Extra: r.Extra, ConfigVer: r.ConfigVer,
		}
	}
	return result, nil
}

func (s *dbGrpcStore) UpdateAgentStatus(id, status string) error {
	return s.db.UpdateAgentStatus(id, status)
}

func startGRPC(addr, certDir, caDir string, store grpc.AgentStore) error {
	grpcServer, err := grpc.NewGRPCServer(addr, certDir, caDir, store)
	if err != nil {
		return fmt.Errorf("failed to create gRPC server: %v", err)
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			grpcServer.CleanupStaleConnections()
		}
	}()

	return grpcServer.Start(addr)
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
