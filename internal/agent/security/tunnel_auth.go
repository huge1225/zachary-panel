package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// TunnelAuthHeaderSize = 8 bytes Unix timestamp + 16 bytes random nonce + 1 byte stream mode + 32 bytes HMAC-SHA256 digest.
const TunnelAuthHeaderSize = 8 + 16 + 1 + 32

// tunnelAuthWindow is the accepted clock skew (seconds) for tunnel auth headers.
const tunnelAuthWindow = 60

// Tunnel stream modes carried inside the authenticated header.
const (
	TunnelModeTCP     byte = 0x01 // 普通 TCP 字节流
	TunnelModeUDP     byte = 0x02 // UDP 数据报按 2 字节长度前缀封装在加密隧道内
	TunnelModeTCPMeta byte = 0x03 // 带原始客户端源地址元数据的 TCP 流（跨多跳透传真实 IP 供出口生成 PROXY Protocol）
	TunnelModeUDPMeta byte = 0x04 // 带原始客户端源地址元数据的 UDP 流
	TunnelModeMux     byte = 0x05 // 常驻连接池多路复用主干会话 (Mux Trunk)
	TunnelModeBond    byte = 0x06 // 单连接多通道条带化聚合子链路 (Bonded Link)
)

func isValidTunnelMode(mode byte) bool {
	return mode >= TunnelModeTCP && mode <= TunnelModeBond
}

// tunnelNonceCache remembers nonces of accepted tunnel headers so a captured header cannot be replayed
// within the timestamp window. Entries are only inserted after a valid HMAC, so unauthenticated peers cannot fill it.
type tunnelNonceCache struct {
	mu     sync.Mutex
	seen   map[string]int64
	lastGC int64
}

const maxTunnelNonceEntries = 200000

var globalTunnelNonces = &tunnelNonceCache{seen: make(map[string]int64)}

func (c *tunnelNonceCache) accept(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().Unix()
	if now-c.lastGC > 30 || len(c.seen) > maxTunnelNonceEntries {
		for k, ts := range c.seen {
			if now-ts > tunnelAuthWindow*2+10 {
				delete(c.seen, k)
			}
		}
		c.lastGC = now
	}
	if len(c.seen) > maxTunnelNonceEntries {
		return false
	}
	if _, dup := c.seen[key]; dup {
		return false
	}
	c.seen[key] = now
	return true
}

func tunnelMAC(secretKey string, ts []byte, nonce []byte, mode byte, ruleID uint64) []byte {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte("nexus-tunnel-auth-v2"))
	mac.Write(ts)
	mac.Write(nonce)
	mac.Write([]byte{mode})
	var ruleBytes [8]byte
	binary.BigEndian.PutUint64(ruleBytes[:], ruleID)
	mac.Write(ruleBytes[:])
	return mac.Sum(nil)
}

// WriteTunnelAuthHeader is called by Ingress / Hop nodes immediately after dialing the next tunnel peer
// to prove possession of the rule's TunnelSecret.
func WriteTunnelAuthHeader(conn net.Conn, ruleID uint64, secretKey string, mode byte) error {
	if secretKey == "" {
		return fmt.Errorf("tunnel secret key is empty")
	}
	if !isValidTunnelMode(mode) {
		return fmt.Errorf("invalid tunnel mode %d", mode)
	}
	var header [TunnelAuthHeaderSize]byte
	binary.BigEndian.PutUint64(header[0:8], uint64(time.Now().Unix()))
	if _, err := rand.Read(header[8:24]); err != nil {
		return err
	}
	header[24] = mode
	copy(header[25:], tunnelMAC(secretKey, header[0:8], header[8:24], mode, ruleID))

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write(header[:])
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

// VerifyTunnelAuthHeader is called by Hop / Egress nodes before forwarding any traffic.
// Unauthorized port scanners, replayed headers, or attackers without the rule's TunnelSecret are dropped.
// It returns the authenticated stream mode.
func VerifyTunnelAuthHeader(conn net.Conn, ruleID uint64, secretKey string) (byte, error) {
	if secretKey == "" {
		return 0, fmt.Errorf("tunnel secret key is empty")
	}
	var header [TunnelAuthHeaderSize]byte
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.ReadFull(conn, header[:])
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return 0, fmt.Errorf("tunnel auth read timeout or short header: %w", err)
	}

	ts := int64(binary.BigEndian.Uint64(header[0:8]))
	diff := time.Now().Unix() - ts
	if diff < -tunnelAuthWindow || diff > tunnelAuthWindow {
		return 0, fmt.Errorf("tunnel auth timestamp expired (diff=%ds)", diff)
	}
	mode := header[24]
	expectedMAC := tunnelMAC(secretKey, header[0:8], header[8:24], mode, ruleID)
	if subtle.ConstantTimeCompare(header[25:], expectedMAC) != 1 {
		return 0, fmt.Errorf("tunnel auth HMAC mismatch: unauthorized scanner or client")
	}
	if !isValidTunnelMode(mode) {
		return 0, fmt.Errorf("unknown tunnel stream mode %d", mode)
	}
	cacheKey := fmt.Sprintf("%d:%s", ruleID, hex.EncodeToString(header[8:24]))
	if !globalTunnelNonces.accept(cacheKey) {
		return 0, fmt.Errorf("tunnel auth replay detected")
	}
	return mode, nil
}

// WriteTunnelClientMeta writes a 1-byte length-prefixed client address ("ip:port", <= 128 bytes) onto an
// already-authenticated tunnel stream so downstream hops and Egress preserve the original visitor IP.
func WriteTunnelClientMeta(conn net.Conn, clientAddr string) error {
	if len(clientAddr) > 128 {
		clientAddr = ""
	}
	if clientAddr != "" {
		if h, p, err := net.SplitHostPort(clientAddr); err != nil || net.ParseIP(h) == nil || len(p) == 0 {
			clientAddr = ""
		}
	}
	buf := make([]byte, 1+len(clientAddr))
	buf[0] = byte(len(clientAddr))
	copy(buf[1:], clientAddr)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write(buf)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

// ReadTunnelClientMeta reads a 1-byte length-prefixed client address ("ip:port", <= 128 bytes) from an
// already-authenticated tunnel stream. Invalid or oversized metadata fails closed.
func ReadTunnelClientMeta(conn net.Conn) (string, error) {
	var lenBuf [1]byte
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		_ = conn.SetReadDeadline(time.Time{})
		return "", err
	}
	n := int(lenBuf[0])
	if n == 0 {
		_ = conn.SetReadDeadline(time.Time{})
		return "", nil
	}
	if n > 128 {
		_ = conn.SetReadDeadline(time.Time{})
		return "", fmt.Errorf("tunnel client metadata length %d exceeds 128", n)
	}
	raw := make([]byte, n)
	_, err := io.ReadFull(conn, raw)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return "", err
	}
	addr := string(raw)
	if h, p, sErr := net.SplitHostPort(addr); sErr != nil || net.ParseIP(h) == nil || len(p) == 0 {
		return "", fmt.Errorf("invalid tunnel client metadata %q", addr)
	}
	return addr, nil
}
