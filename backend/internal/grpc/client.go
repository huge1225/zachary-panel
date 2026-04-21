package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GRPCClient gRPC客户端（Agent端使用，连接到Panel）
type GRPCClient struct {
	conn        *grpc.ClientConn
	panelClient PanelServiceClient
}

// NewGRPCClient 创建gRPC客户端
func NewGRPCClient(addr, certDir, caDir string) (*GRPCClient, error) {
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "tls.crt"),
		filepath.Join(certDir, "tls.key"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load client TLS cert: %v", err)
	}

	caCertPEM, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCertPEM)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
	}

	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}

	return &GRPCClient{
		conn:        conn,
		panelClient: NewPanelServiceClient(conn),
	}, nil
}

// Close 关闭连接
func (c *GRPCClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// RegisterAgent 注册Agent
func (c *GRPCClient) RegisterAgent(req *RegisterRequest) (*RegisterResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.panelClient.RegisterAgent(ctx, req)
}

// GetForwardRules 获取转发规则
func (c *GRPCClient) GetForwardRules(agentID string) (*GetRulesResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.panelClient.GetForwardRules(ctx, &GetRulesRequest{AgentId: agentID})
}

// Heartbeat 发送心跳
func (c *GRPCClient) Heartbeat(agentID string) (*HeartbeatResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.panelClient.Heartbeat(ctx, &HeartbeatRequest{AgentId: agentID})
}

var _ = emptypb.Empty{}
