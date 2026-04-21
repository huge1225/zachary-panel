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
)

// RegisterClient 注册客户端
type RegisterClient struct {
	conn   *grpc.ClientConn
	client PanelServiceClient
}

// NewRegisterClient 创建注册客户端
func NewRegisterClient(addr, certDir, caDir string) (*RegisterClient, error) {
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

	return &RegisterClient{
		conn:   conn,
		client: NewPanelServiceClient(conn),
	}, nil
}

// Close 关闭连接
func (c *RegisterClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// DoRegister 注册Agent
func (c *RegisterClient) DoRegister(id, hostname, ip, os_, arch, token string) (*RegisterResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return c.client.RegisterAgent(ctx, &RegisterRequest{
		Id:       id,
		Hostname: hostname,
		Ip:       ip,
		Os:       os_,
		Arch:     arch,
		Token:    token,
	})
}
