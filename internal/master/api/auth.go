package api

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
	"nexus-panel/internal/master/model"
)

const (
	minPasswordLen = 8
	maxPasswordLen = 72 // bcrypt only uses the first 72 bytes

	accountLockThreshold = 10
	accountLockDuration  = 15 * time.Minute
)

var (
	jwtSecretMu sync.RWMutex
	jwtSecret   = ephemeralJWTSecret()

	// dummyHash is compared against when the account does not exist so that response time does not reveal
	// whether an email is registered.
	dummyHash, _ = bcrypt.GenerateFromPassword([]byte("zachary-panel-dummy-password"), bcrypt.DefaultCost)

	loginLimiter    = newKeyedLimiter(rate.Every(6*time.Second), 5)  // per client IP: ~10/min, burst 5
	sensitiveLimits = newKeyedLimiter(rate.Every(3*time.Second), 10) // per user: redeem / probe / password
	accountGuard    = newAccountLockout()
)

func ephemeralJWTSecret() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return []byte(hex.EncodeToString(b))
}

// SetJWTSecret installs the persistent JWT signing key (loaded by cmd/master from env or the data directory).
func SetJWTSecret(secret []byte) {
	if len(secret) < 32 {
		log.Println("[Security] Refusing JWT secret shorter than 32 bytes; keeping ephemeral random key")
		return
	}
	jwtSecretMu.Lock()
	jwtSecret = append([]byte(nil), secret...)
	jwtSecretMu.Unlock()
}

func currentJWTSecret() []byte {
	jwtSecretMu.RLock()
	defer jwtSecretMu.RUnlock()
	return jwtSecret
}

// keyedLimiter is a token-bucket limiter per key with periodic garbage collection of idle keys.
type keyedLimiter struct {
	mu     sync.Mutex
	every  rate.Limit
	burst  int
	m      map[string]*limEntry
	lastGC time.Time
}

type limEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

func newKeyedLimiter(every rate.Limit, burst int) *keyedLimiter {
	return &keyedLimiter{every: every, burst: burst, m: make(map[string]*limEntry)}
}

func (k *keyedLimiter) Allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := time.Now()
	if now.Sub(k.lastGC) > time.Minute {
		for key, e := range k.m {
			if now.Sub(e.lastSeen) > 10*time.Minute {
				delete(k.m, key)
			}
		}
		k.lastGC = now
	}
	e, ok := k.m[key]
	if !ok {
		e = &limEntry{lim: rate.NewLimiter(k.every, k.burst)}
		k.m[key] = e
	}
	e.lastSeen = now
	return e.lim.Allow()
}

// accountLockout throttles password guessing on two levels:
//   - per (email, client IP): 10 failures -> 15 min lock. One attacker IP can only lock itself out, never the owner;
//   - per email (all IPs): 100 failures -> 15 min lock against distributed guessing. Clients that have logged in
//     successfully for this account recently ("known IPs") are exempt, so a distributed attacker cannot lock the
//     legitimate administrator out either.
type accountLockout struct {
	mu      sync.Mutex
	entries map[string]*lockEntry
	known   map[string]map[string]time.Time // email -> client IP -> last successful login
}

type lockEntry struct {
	fails       int
	lockedUntil time.Time
	lastFail    time.Time
}

const (
	accountGlobalLockThreshold = 100
	knownIPTTL                 = 30 * 24 * time.Hour
	maxKnownIPsPerAccount      = 32
)

func newAccountLockout() *accountLockout {
	return &accountLockout{entries: make(map[string]*lockEntry), known: make(map[string]map[string]time.Time)}
}

func (a *accountLockout) isKnownLocked(email, ip string) bool {
	if m, ok := a.known[email]; ok {
		if t, ok := m[ip]; ok && time.Since(t) < knownIPTTL {
			return true
		}
	}
	return false
}

func (a *accountLockout) activeLocked(key string) bool {
	e, ok := a.entries[key]
	return ok && time.Now().Before(e.lockedUntil)
}

func (a *accountLockout) locked(email, ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.activeLocked("pair|" + email + "|" + ip) {
		return true
	}
	return a.activeLocked("acct|"+email) && !a.isKnownLocked(email, ip)
}

func (a *accountLockout) bumpLocked(key string, threshold int, now time.Time) {
	e, ok := a.entries[key]
	if !ok || now.Sub(e.lastFail) > accountLockDuration {
		e = &lockEntry{}
		a.entries[key] = e
	}
	e.fails++
	e.lastFail = now
	if e.fails >= threshold {
		e.lockedUntil = now.Add(accountLockDuration)
		e.fails = 0
	}
}

func (a *accountLockout) fail(email, ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if len(a.entries) > 20000 {
		for k, e := range a.entries {
			if now.Sub(e.lastFail) > accountLockDuration && now.After(e.lockedUntil) {
				delete(a.entries, k)
			}
		}
	}
	a.bumpLocked("pair|"+email+"|"+ip, accountLockThreshold, now)
	a.bumpLocked("acct|"+email, accountGlobalLockThreshold, now)
}

// success clears the per-IP failure state and remembers the IP as known-good for this account.
func (a *accountLockout) success(email, ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.entries, "pair|"+email+"|"+ip)
	m, ok := a.known[email]
	if !ok {
		if len(a.known) > 20000 {
			a.known = make(map[string]map[string]time.Time)
		}
		m = make(map[string]time.Time)
		a.known[email] = m
	}
	if len(m) >= maxKnownIPsPerAccount {
		var oldestIP string
		var oldest time.Time
		for k, t := range m {
			if oldestIP == "" || t.Before(oldest) {
				oldestIP, oldest = k, t
			}
		}
		delete(m, oldestIP)
	}
	m[ip] = time.Now()
}

// reset clears all lockout state for an account (used by tests / admin tooling).
func (a *accountLockout) reset(email string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k := range a.entries {
		if k == "acct|"+email || strings.HasPrefix(k, "pair|"+email+"|") {
			delete(a.entries, k)
		}
	}
}

func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func validEmail(email string) bool {
	if email == "" || len(email) > 191 {
		return false
	}
	addr, err := mail.ParseAddress(email)
	return err == nil && addr.Address == email && strings.Contains(email, "@")
}

func validPassword(pw string) bool {
	return len(pw) >= minPasswordLen && len(pw) <= maxPasswordLen
}

type Claims struct {
	UserID       uint64 `json:"user_id"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	TokenVersion int    `json:"tv"`
	jwt.RegisteredClaims
}

func GenerateToken(u *model.User) (string, error) {
	claims := Claims{
		UserID:       u.ID,
		Email:        u.Email,
		Role:         u.Role,
		TokenVersion: u.TokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(currentJWTSecret())
}

func (s *Server) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization token"})
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		var claims Claims
		token, err := jwt.ParseWithClaims(
			tokenStr,
			&claims,
			func(t *jwt.Token) (any, error) {
				return currentJWTSecret(), nil
			},
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
			jwt.WithExpirationRequired(),
		)
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		// Verify live user status, role and token version in database so banned/downgraded accounts and tokens
		// issued before a password change are revoked immediately.
		var user model.User
		if err := s.db.Select("id, role, status, token_version").First(&user, claims.UserID).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}
		if user.TokenVersion != claims.TokenVersion {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}
		if user.Status == "banned" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "账号已被封禁"})
			return
		}

		c.Set("user_id", user.ID)
		c.Set("user_role", user.Role)
		c.Next()
	}
}

func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("user_role")
		if role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "administrator privileges required"})
			return
		}
		c.Next()
	}
}

// userRateLimit applies a per-user rate limit to expensive or abuse-prone endpoints.
func userRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		uid, _ := c.Get("user_id")
		key := c.FullPath() + "|" + toKey(uid)
		if !sensitiveLimits.Allow(key) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "操作过于频繁，请稍后再试"})
			return
		}
		c.Next()
	}
}

// ruleMutationLimiter is one shared budget per user for all rule create/update/toggle/delete calls. Each mutation
// reconfigures engines on shared nodes (e.g. realm reloads), so unthrottled loops would disrupt other tenants.
var ruleMutationLimiter = newKeyedLimiter(rate.Every(2*time.Second), 20)

func ruleMutationLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if role, _ := c.Get("user_role"); role == "admin" {
			c.Next()
			return
		}
		uid, _ := c.Get("user_id")
		if !ruleMutationLimiter.Allow("rules|" + toKey(uid)) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "规则变更过于频繁，请稍后再试"})
			return
		}
		c.Next()
	}
}

func toKey(v any) string {
	if id, ok := v.(uint64); ok {
		return strconv.FormatUint(id, 10)
	}
	return "anon"
}

func (s *Server) handleLogin(c *gin.Context) {
	if !loginLimiter.Allow("ip:" + c.ClientIP()) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "登录尝试过于频繁，请稍后再试"})
		return
	}

	var req struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入邮箱和密码"})
		return
	}
	email := normalizeEmail(req.Email)
	if len(email) > 191 || len(req.Password) > 1024 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "邮箱或密码错误"})
		return
	}
	clientIP := c.ClientIP()
	if accountGuard.locked(email, clientIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "该账号登录失败次数过多，已临时锁定，请稍后再试"})
		return
	}

	var user model.User
	if err := s.db.Where("LOWER(email) = ?", email).First(&user).Error; err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
		accountGuard.fail(email, clientIP)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "邮箱或密码错误"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		accountGuard.fail(email, clientIP)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "邮箱或密码错误"})
		return
	}
	if user.Status == "banned" {
		c.JSON(http.StatusForbidden, gin.H{"error": "账号已被封禁"})
		return
	}
	accountGuard.success(email, clientIP)

	token, err := GenerateToken(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  user,
	})
}

func (s *Server) handleRegister(c *gin.Context) {
	if !loginLimiter.Allow("ip:" + c.ClientIP()) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "请求过于频繁，请稍后再试"})
		return
	}

	cfg := s.getSystemConfig()
	if !cfg.AllowRegister {
		c.JSON(http.StatusForbidden, gin.H{"error": "管理员已关闭公开注册"})
		return
	}

	var req struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入有效邮箱且密码为 8-72 位"})
		return
	}

	email := normalizeEmail(req.Email)
	if !validEmail(email) || !validPassword(req.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入有效邮箱且密码为 8-72 位"})
		return
	}
	var count int64
	s.db.Model(&model.User{}).Where("LOWER(email) = ?", email).Count(&count)
	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "该邮箱已注册"})
		return
	}

	quotaBytes := cfg.DefaultQuotaGB * 1024 * 1024 * 1024
	if quotaBytes <= 0 {
		quotaBytes = 10 * 1024 * 1024 * 1024
	}
	maxRules := cfg.DefaultMaxRules
	if maxRules <= 0 {
		maxRules = 5
	}
	speedMbps := cfg.DefaultSpeedMbps
	if speedMbps <= 0 {
		speedMbps = 50
	}

	roleGroupID := cfg.DefaultRoleGroupID
	if roleGroupID == 0 {
		roleGroupID = 1
	}
	allowedTunnels := cfg.DefaultTunnels
	var rg model.RoleGroup
	if err := s.db.First(&rg, roleGroupID).Error; err == nil {
		allowedTunnels = rg.AllowedTunnels
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "注册失败，请稍后再试"})
		return
	}
	user := model.User{
		Email:          email,
		PasswordHash:   string(hash),
		Role:           "user",
		Status:         "active",
		RoleGroupID:    roleGroupID,
		PlanID:         cfg.DefaultPlanID,
		AllowedTunnels: allowedTunnels,
		QuotaBytes:     quotaBytes,
		MaxRules:       maxRules,
		SpeedMbps:      speedMbps,
		ExpireAt:       time.Now().AddDate(0, 0, 7),
	}
	if err := s.db.Create(&user).Error; err != nil {
		log.Printf("[API] register failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "注册失败，请稍后再试"})
		return
	}

	token, _ := GenerateToken(&user)
	c.JSON(http.StatusCreated, gin.H{
		"token": token,
		"user":  user,
	})
}

// handleChangePassword lets a logged-in user change their own password. All previously issued tokens are revoked.
func (s *Server) handleChangePassword(c *gin.Context) {
	uid := c.MustGet("user_id").(uint64)
	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请填写原密码和新密码"})
		return
	}
	if !validPassword(req.NewPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "新密码长度需为 8-72 位"})
		return
	}
	var user model.User
	if err := s.db.First(&user, uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.OldPassword)); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "原密码错误"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "修改失败，请稍后再试"})
		return
	}
	if err := s.db.Model(&model.User{}).Where("id = ?", uid).Updates(map[string]any{
		"password_hash": string(hash),
		"token_version": gorm.Expr("token_version + 1"),
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "修改失败，请稍后再试"})
		return
	}
	_ = s.db.First(&user, uid).Error
	token, _ := GenerateToken(&user)
	c.JSON(http.StatusOK, gin.H{"message": "密码已修改，其他设备上的登录已失效", "token": token})
}
