package api

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"nexus-panel/internal/master/model"
)

var (
	jwtSecret    = initJWTSecret()
	loginGuardMu sync.Mutex
	loginLimMap  = make(map[string]*rate.Limiter)
)

func initJWTSecret() []byte {
	if envKey := strings.TrimSpace(os.Getenv("NEXUS_JWT_SECRET")); len(envKey) >= 16 {
		return []byte(envKey)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err == nil {
		log.Println("[Security] NEXUS_JWT_SECRET not set; generated ephemeral 256-bit random JWT signing key")
		return []byte(hex.EncodeToString(b))
	}
	return []byte("nexus-fallback-ephemeral-secret-key")
}

func allowLoginAttempt(clientIP string) bool {
	loginGuardMu.Lock()
	defer loginGuardMu.Unlock()
	lim, ok := loginLimMap[clientIP]
	if !ok {
		// Allow 10 attempts per minute with burst of 5 per IP
		lim = rate.NewLimiter(rate.Every(6*time.Second), 5)
		loginLimMap[clientIP] = lim
	}
	return lim.Allow()
}

type Claims struct {
	UserID uint64 `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func GenerateToken(u *model.User) (string, error) {
	claims := Claims{
		UserID: u.ID,
		Email:  u.Email,
		Role:   u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
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
				return jwtSecret, nil
			},
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		)
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		// Verify live user status and role in database so banned/downgraded accounts are revoked immediately
		var user model.User
		if err := s.db.Select("id, role, status").First(&user, claims.UserID).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user account no longer exists"})
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

func (s *Server) handleLogin(c *gin.Context) {
	if !allowLoginAttempt(c.ClientIP()) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "登录尝试过于频繁，请稍后再试"})
		return
	}

	var req struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user model.User
	if err := s.db.Where("email = ?", strings.TrimSpace(req.Email)).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "邮箱或密码错误"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "邮箱或密码错误"})
		return
	}
	if user.Status == "banned" {
		c.JSON(http.StatusForbidden, gin.H{"error": "账号已被封禁"})
		return
	}

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
	if !allowLoginAttempt(c.ClientIP()) {
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
		Password string `json:"password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入有效邮箱且密码不少于8位"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	var count int64
	s.db.Model(&model.User{}).Where("email = ?", email).Count(&count)
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

	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	token, _ := GenerateToken(&user)
	c.JSON(http.StatusCreated, gin.H{
		"token": token,
		"user":  user,
	})
}
