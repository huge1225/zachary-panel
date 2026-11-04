package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const (
	// MaxClockSkewSeconds defines the allowed timestamp window (±60s) to prevent replay attacks.
	MaxClockSkewSeconds = 60
)

// GenerateNonce creates a random 16-byte hex nonce for message uniqueness.
func GenerateNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// SignEnvelope populates Timestamp, Nonce, and HMAC-SHA256 Signature on an Envelope using the node's SecretToken.
func SignEnvelope(msgType MessageType, payload any, secretToken string) (Envelope, error) {
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	now := time.Now().Unix()
	nonce := GenerateNonce()
	sig := computeHMAC(msgType, now, nonce, rawPayload, secretToken)

	return Envelope{
		Type:      msgType,
		Timestamp: now,
		Nonce:     nonce,
		Signature: sig,
		Payload:   json.RawMessage(rawPayload),
	}, nil
}

// VerifyEnvelope checks the timestamp window, replay cache, and HMAC-SHA256 signature of a received raw message.
func VerifyEnvelope(raw []byte, secretToken string, replayGuard *ReplayGuard) (*Envelope, []byte, error) {
	var env struct {
		Type      MessageType     `json:"type"`
		RequestID string          `json:"request_id,omitempty"`
		Timestamp int64           `json:"timestamp"`
		Nonce     string          `json:"nonce"`
		Signature string          `json:"signature"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, fmt.Errorf("malformed envelope json: %w", err)
	}

	now := time.Now().Unix()
	diff := now - env.Timestamp
	if diff < -MaxClockSkewSeconds || diff > MaxClockSkewSeconds {
		return nil, nil, fmt.Errorf("envelope timestamp expired or skewed (diff=%ds)", diff)
	}

	if env.Nonce == "" || env.Signature == "" {
		return nil, nil, fmt.Errorf("missing security nonce or HMAC signature")
	}

	expectedSig := computeHMAC(env.Type, env.Timestamp, env.Nonce, env.Payload, secretToken)
	if subtle.ConstantTimeCompare([]byte(env.Signature), []byte(expectedSig)) != 1 {
		return nil, nil, fmt.Errorf("invalid HMAC signature: message tampered or unauthorized")
	}

	if replayGuard != nil && !replayGuard.Accept(env.Nonce, env.Timestamp) {
		return nil, nil, fmt.Errorf("replay attack detected: duplicate nonce %s", env.Nonce)
	}

	parsed := &Envelope{
		Type:      env.Type,
		RequestID: env.RequestID,
		Timestamp: env.Timestamp,
		Nonce:     env.Nonce,
		Signature: env.Signature,
	}
	return parsed, env.Payload, nil
}

// ComputeHandshakeAuth generates the WebSocket handshake authentication signature.
func ComputeHandshakeAuth(nodeID uint64, timestamp int64, nonce string, secretToken string) string {
	mac := hmac.New(sha256.New, []byte(secretToken))
	mac.Write([]byte(fmt.Sprintf("handshake:%d:%d:%s", nodeID, timestamp, nonce)))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHandshakeAuth validates the Agent's WebSocket upgrade headers without exposing the raw token in URLs.
func VerifyHandshakeAuth(nodeID uint64, timestamp int64, nonce string, signature string, secretToken string) error {
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < -MaxClockSkewSeconds || diff > MaxClockSkewSeconds {
		return fmt.Errorf("handshake timestamp out of window (diff=%ds)", diff)
	}
	if len(nonce) < 16 {
		return fmt.Errorf("invalid handshake nonce")
	}
	expected := ComputeHandshakeAuth(nodeID, timestamp, nonce, secretToken)
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) != 1 {
		return fmt.Errorf("handshake HMAC signature mismatch")
	}
	return nil
}

func computeHMAC(msgType MessageType, ts int64, nonce string, rawPayload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%s|%d|%s|", msgType, ts, nonce)))
	mac.Write(rawPayload)
	return hex.EncodeToString(mac.Sum(nil))
}

// ReplayGuard maintains a sliding window of seen nonces to reject replayed frames.
type ReplayGuard struct {
	mu      sync.Mutex
	seen    map[string]int64
	lastGC  int64
}

func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{
		seen:   make(map[string]int64),
		lastGC: time.Now().Unix(),
	}
}

func (r *ReplayGuard) Accept(nonce string, ts int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().Unix()
	if now-r.lastGC > 30 {
		for k, exp := range r.seen {
			if now-exp > MaxClockSkewSeconds*2 {
				delete(r.seen, k)
			}
		}
		r.lastGC = now
	}

	if _, exists := r.seen[nonce]; exists {
		return false
	}
	r.seen[nonce] = ts
	return true
}
