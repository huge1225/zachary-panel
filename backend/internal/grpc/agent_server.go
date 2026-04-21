package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// RunAgentServer 运行Agent gRPC服务器（接收Panel推送的配置）
func RunAgentServer(addr, certDir, caDir string, agent *Agent) error {
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "tls.crt"),
		filepath.Join(certDir, "tls.key"),
	)
	if err != nil {
		return fmt.Errorf("failed to load TLS cert: %v", err)
	}

	caCertPEM, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %v", err)
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

	RegisterAgentServiceServer(s, agent)

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	fmt.Printf("Agent gRPC server starting on %s with mTLS\n", addr)
	return s.Serve(lis)
}
