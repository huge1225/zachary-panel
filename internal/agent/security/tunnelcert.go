package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"nexus-panel/pkg/protocol"
)

// TunnelCert is the persistent TLS identity an Agent presents when acting as a tunnel Egress.
// The public certificate is reported to Master, which distributes it to paired Ingress nodes for pinning.
type TunnelCert struct {
	TLS      tls.Certificate
	CertPEM  string
	CertFile string
	KeyFile  string
}

// LoadOrCreateTunnelCert loads <dir>/tunnel-cert.pem + tunnel-key.pem, or generates a new ECDSA P-256
// self-signed certificate (SAN = protocol.TunnelServerName) if missing / invalid / close to expiry.
func LoadOrCreateTunnelCert(dir string) (*TunnelCert, error) {
	certFile := filepath.Join(dir, "tunnel-cert.pem")
	keyFile := filepath.Join(dir, "tunnel-key.pem")

	if certPEM, err := os.ReadFile(certFile); err == nil {
		if keyPEM, err := os.ReadFile(keyFile); err == nil {
			if pair, err := tls.X509KeyPair(certPEM, keyPEM); err == nil {
				if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil && time.Now().Add(30*24*time.Hour).Before(leaf.NotAfter) {
					return &TunnelCert{TLS: pair, CertPEM: string(certPEM), CertFile: certFile, KeyFile: keyFile}, nil
				}
			}
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: protocol.TunnelServerName},
		DNSNames:              []string{protocol.TunnelServerName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := writeFileAtomic(keyFile, keyPEM, 0600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(certFile, certPEM, 0600); err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &TunnelCert{TLS: pair, CertPEM: string(certPEM), CertFile: certFile, KeyFile: keyFile}, nil
}

// TunnelClientTLSConfig builds an Ingress-side TLS config that only trusts the pinned Egress certificate.
func TunnelClientTLSConfig(certPEM string) (*tls.Config, error) {
	if certPEM == "" {
		return nil, fmt.Errorf("egress tunnel certificate not registered yet (egress agent offline or outdated)")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(certPEM)) {
		return nil, fmt.Errorf("invalid egress tunnel certificate PEM")
	}
	return &tls.Config{
		RootCAs:    pool,
		ServerName: protocol.TunnelServerName,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// ValidateTunnelCertPEM checks that a PEM blob is a single parseable X.509 certificate for the tunnel server name.
func ValidateTunnelCertPEM(certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if err := cert.VerifyHostname(protocol.TunnelServerName); err != nil {
		return err
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// WriteFileAtomic exposes atomic 0600-style writes for engine configuration files.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomic(path, data, perm)
}
