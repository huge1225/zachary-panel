package limiter

import (
	"context"
	"io"
	"net"
	"sync/atomic"

	"golang.org/x/time/rate"
)

// RuleStatsTracker tracks atomic byte counters and active connections for a forwarding rule.
type RuleStatsTracker struct {
	UploadBytes int64
	DownBytes   int64
	ActiveConns int64
	Limiter     *rate.Limiter
}

// NewRuleStatsTracker creates a tracker with an optional bandwidth limit in Mbps.
func NewRuleStatsTracker(speedLimitMbps int) *RuleStatsTracker {
	var lim *rate.Limiter
	if speedLimitMbps > 0 {
		// Convert Mbps to Bytes per second: 1 Mbps = 125,000 Bytes/s
		bytesPerSec := float64(speedLimitMbps) * 125000.0
		burst := int(bytesPerSec)
		if burst < 64*1024 {
			burst = 64 * 1024
		}
		lim = rate.NewLimiter(rate.Limit(bytesPerSec), burst)
	}
	return &RuleStatsTracker{
		Limiter: lim,
	}
}

// AddUpload atomically adds uploaded bytes.
func (t *RuleStatsTracker) AddUpload(n int64) {
	atomic.AddInt64(&t.UploadBytes, n)
}

// AddDownload atomically adds downloaded bytes.
func (t *RuleStatsTracker) AddDownload(n int64) {
	atomic.AddInt64(&t.DownBytes, n)
}

// SwapDeltas atomically reads and resets the upload/download counters while preserving active conns.
func (t *RuleStatsTracker) SwapDeltas() (up int64, down int64, active int64) {
	up = atomic.SwapInt64(&t.UploadBytes, 0)
	down = atomic.SwapInt64(&t.DownBytes, 0)
	active = atomic.LoadInt64(&t.ActiveConns)
	return
}

// CopyWithStats copies from src to dst while enforcing rate limits and counting bytes in counterPtr.
func CopyWithStats(ctx context.Context, dst io.Writer, src io.Reader, lim *rate.Limiter, counterPtr *int64) error {
	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if lim != nil {
				if err := lim.WaitN(ctx, nr); err != nil {
					return err
				}
			}
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				atomic.AddInt64(counterPtr, int64(nw))
			}
			if ew != nil {
				return ew
			}
			if nr != nw {
				return io.ErrShortWrite
			}
		}
		if er != nil {
			if er != io.EOF {
				return er
			}
			return nil
		}
	}
}

// WrapConnWithStats wraps a net.Conn if upper layers need transparent counting.
type TrackedConn struct {
	net.Conn
	ctx     context.Context
	tracker *RuleStatsTracker
}
