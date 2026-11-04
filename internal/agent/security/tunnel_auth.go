package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// TunnelAuthHeaderSize = 8 bytes Unix timestamp + 32 bytes HMAC-SHA256 digest = 40 bytes.
const TunnelAuthHeaderSize = 40

// WriteTunnelAuthHeader is called by the Ingress Node immediately after dialing the Egress Node
// to prove possession of the rule's TunnelSecret.
func WriteTunnelAuthHeader(conn net.Conn, ruleID uint64, secretKey string) error {
	if secretKey == "" {
		return nil
	}
	now := time.Now().Unix()
	var header [TunnelAuthHeaderSize]byte
	binary.BigEndian.PutUint64(header[0:8], uint64(now))

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(header[0:8])
	var ruleBytes [8]byte
	binary.BigEndian.PutUint64(ruleBytes[:], ruleID)
	mac.Write(ruleBytes[:])
	copy(header[8:40], mac.Sum(nil))

	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err := conn.Write(header[:])
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

// VerifyTunnelAuthHeader is called by the Egress Node before forwarding any traffic.
// Unauthorized port scanners or attackers without the rule's TunnelSecret are dropped within 3 seconds.
func VerifyTunnelAuthHeader(conn net.Conn, ruleID uint64, secretKey string) error {
	if secretKey == "" {
		return nil
	}
	var header [TunnelAuthHeaderSize]byte
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := io.ReadFull(conn, header[:])
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("tunnel auth read timeout or short header: %w", err)
	}

	ts := int64(binary.BigEndian.Uint64(header[0:8]))
	diff := time.Now().Unix() - ts
	if diff < -60 || diff > 60 {
		return fmt.Errorf("tunnel auth timestamp expired (diff=%ds)", diff)
	}

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(header[0:8])
	var ruleBytes [8]byte
	binary.BigEndian.PutUint64(ruleBytes[:], ruleID)
	mac.Write(ruleBytes[:])
	expectedMAC := mac.Sum(nil)

	if subtle.ConstantTimeCompare(header[8:40], expectedMAC) != 1 {
		return fmt.Errorf("tunnel auth HMAC mismatch: unauthorized scanner or client")
	}
	return nil
}
