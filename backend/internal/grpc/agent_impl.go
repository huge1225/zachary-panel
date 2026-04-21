package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// Agent gRPC Agent实现
type Agent struct {
	UnimplementedAgentServiceServer
	configStream AgentService_PushConfigServer
	configChan   chan *ConfigUpdate
	mu           sync.Mutex
}

// NewAgent 创建Agent
func NewAgent() *Agent {
	return &Agent{
		configChan: make(chan *ConfigUpdate, 100),
	}
}

// PushConfig Panel推送配置（Agent端作为Server接收配置流）
func (a *Agent) PushConfig(stream AgentService_PushConfigServer) error {
	a.mu.Lock()
	a.configStream = stream
	a.mu.Unlock()

	log.Println("[agent] Config stream started")
	defer log.Println("[agent] Config stream ended")

	for {
		config, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&ConfigResponse{Success: true, Message: "Done"})
		}
		if err != nil {
			return status.Errorf(codes.Internal, "receive failed: %v", err)
		}

		log.Printf("[agent] Received config: %d rules", len(config.Rules))

		select {
		case a.configChan <- config:
		default:
			log.Println("[agent] Config channel full, dropping update")
		}
	}
}

// GetConfigChan 获取配置通道
func (a *Agent) GetConfigChan() <-chan *ConfigUpdate {
	return a.configChan
}

// AgentClient Agent客户端（Panel端使用，连接到Agent推送配置）
type AgentClient struct {
	conn   *grpc.ClientConn
	client AgentServiceClient
}

// NewAgentClient 创建Agent客户端
func NewAgentClient(addr, certDir, caDir string) (*AgentClient, error) {
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

	return &AgentClient{
		conn:   conn,
		client: NewAgentServiceClient(conn),
	}, nil
}

// PushConfigToAgent 推送配置到Agent
func (c *AgentClient) PushConfigToAgent(ctx context.Context, config *ConfigUpdate) (*ConfigResponse, error) {
	stream, err := c.client.PushConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream: %v", err)
	}

	if err := stream.Send(config); err != nil {
		return nil, fmt.Errorf("send failed: %v", err)
	}

	return stream.CloseAndRecv()
}
