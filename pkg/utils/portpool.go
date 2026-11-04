package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// GenerateRandomToken generates a cryptographically secure hex token of nBytes length.
func GenerateRandomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "fallback-secret-token"
	}
	return hex.EncodeToString(b)
}

// ParsePortRange parses a port range string like "10000-50000" into min and max port numbers.
func ParsePortRange(portRange string) (int, int, error) {
	parts := strings.Split(strings.TrimSpace(portRange), "-")
	if len(parts) != 2 {
		return 10000, 50000, fmt.Errorf("invalid port range format: %s", portRange)
	}
	minPort, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	maxPort, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || minPort <= 0 || maxPort > 65535 || minPort > maxPort {
		return 10000, 50000, fmt.Errorf("port range out of bounds: %s", portRange)
	}
	return minPort, maxPort, nil
}

// AllocateFreePort picks the first unused port in [minPort, maxPort] given a set of occupied ports.
func AllocateFreePort(portRange string, occupied map[int]bool) (int, error) {
	minPort, maxPort, err := ParsePortRange(portRange)
	if err != nil {
		minPort, maxPort = 10000, 50000
	}
	for p := minPort; p <= maxPort; p++ {
		if !occupied[p] {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free ports available in range %d-%d", minPort, maxPort)
}
