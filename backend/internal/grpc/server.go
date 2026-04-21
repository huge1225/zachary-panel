package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GRPCServer gRPC服务器（Panel端使用）
type GRPCServer struct {
	UnimplementedPanelServiceServer
	UnimplementedAgentServiceServer
	server *grpc.Server
	store  AgentStore
	agents map[string]*AgentConnection
	mu     sync.RWMutex
}

// AgentConnection Agent连接
type AgentConnection struct {
	lastSeen time.Time
}

// NewGRPCServer 创建gRPC服务器
func NewGRPCServer(addr, certDir, caDir string, store AgentStore) (*GRPCServer, error) {
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "tls.crt"),
		filepath.Join(certDir, "tls.key"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS cert: %v", err)
	}

	caCertPEM, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertPEM)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	creds := credentials.NewTLS(tlsConfig)
	s := grpc.NewServer(grpc.Creds(creds))

	grpcServer := &GRPCServer{
		server: s,
		store:  store,
		agents: make(map[string]*AgentConnection),
	}

	RegisterPanelServiceServer(s, grpcServer)
	RegisterAgentServiceServer(s, grpcServer)

	return grpcServer, nil
}

// Start 启动gRPC服务器
func (s *GRPCServer) Start(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	log.Printf("gRPC server starting on %s with mTLS", addr)
	return s.server.Serve(lis)
}

// Stop 停止gRPC服务器
func (s *GRPCServer) Stop() {
	s.server.GracefulStop()
}

// RegisterAgent Agent注册
func (s *GRPCServer) RegisterAgent(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	log.Printf("Agent registering: %s (%s)", req.Id, req.Ip)

	agent, err := s.store.GetAgent(req.Id)
	if err != nil || agent.Token != req.Token {
		return &RegisterResponse{
			Success: false,
			Message: "Invalid token",
		}, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	if err := s.store.UpdateAgentStatus(req.Id, "online"); err != nil {
		log.Printf("Failed to update agent status: %v", err)
	}

	s.mu.Lock()
	s.agents[req.Id] = &AgentConnection{lastSeen: time.Now()}
	s.mu.Unlock()

	rules, _ := s.store.GetRulesByAgent(req.Id)
	var respRules []*ForwardRule
	for _, rule := range rules {
		respRules = append(respRules, &ForwardRule{
			Id: rule.ID, AgentId: rule.AgentID,
			ListenAddr: rule.ListenAddr, TargetAddr: rule.TargetAddr,
			Protocol: rule.Protocol, Enabled: rule.Enabled,
			Extra: rule.Extra, ConfigVer: rule.ConfigVer,
		})
	}

	log.Printf("Agent %s registered, %d rules loaded", req.Id, len(respRules))
	return &RegisterResponse{
		Success: true,
		Message: "Registration successful",
		Rules:   respRules,
	}, nil
}

// GetForwardRules 获取转发规则
func (s *GRPCServer) GetForwardRules(ctx context.Context, req *GetRulesRequest) (*GetRulesResponse, error) {
	rules, err := s.store.GetRulesByAgent(req.AgentId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get rules: %v", err)
	}

	var respRules []*ForwardRule
	for _, rule := range rules {
		respRules = append(respRules, &ForwardRule{
			Id: rule.ID, AgentId: rule.AgentID,
			ListenAddr: rule.ListenAddr, TargetAddr: rule.TargetAddr,
			Protocol: rule.Protocol, Enabled: rule.Enabled,
			Extra: rule.Extra, ConfigVer: rule.ConfigVer,
		})
	}
	return &GetRulesResponse{Rules: respRules}, nil
}

// UpdateRuleStatus 更新规则状态
func (s *GRPCServer) UpdateRuleStatus(ctx context.Context, req *UpdateRuleStatusRequest) (*UpdateRuleStatusResponse, error) {
	return &UpdateRuleStatusResponse{
		Success: true,
		Message: "Rule status updated",
	}, nil
}

// Heartbeat 心跳检测
func (s *GRPCServer) Heartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error) {
	s.mu.Lock()
	if conn, exists := s.agents[req.AgentId]; exists {
		conn.lastSeen = time.Now()
	}
	s.mu.Unlock()

	s.store.UpdateAgentStatus(req.AgentId, "online")
	return &HeartbeatResponse{Success: true}, nil
}

// PushConfig Panel推送配置到Agent
func (s *GRPCServer) PushConfig(stream AgentService_PushConfigServer) error {
	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			req, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return status.Errorf(codes.Internal, "receive failed: %v", err)
			}
			log.Printf("Config ack from agent %s", req.AgentId)
			if err := stream.SendAndClose(&ConfigResponse{Success: true, Message: "Config received"}); err != nil {
				return status.Errorf(codes.Internal, "send failed: %v", err)
			}
			return nil
		}
	}
}

// CleanupStaleConnections 清理过期连接
func (s *GRPCServer) CleanupStaleConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, conn := range s.agents {
		if time.Since(conn.lastSeen) > 60*time.Second {
			delete(s.agents, id)
			s.store.UpdateAgentStatus(id, "offline")
			log.Printf("Agent %s went offline", id)
		}
	}
}

var _ = emptypb.Empty{}
