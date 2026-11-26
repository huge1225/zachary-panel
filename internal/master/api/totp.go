package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"nexus-panel/internal/master/model"
)

func generateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// ComputeTOTPCodeAtStep computes a 6-digit RFC 6238 TOTP code for an explicit 30-second counter step.
func ComputeTOTPCodeAtStep(secret string, step int64) (string, error) {
	if step < 0 {
		return "", fmt.Errorf("invalid totp step")
	}
	clean := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(step))

	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]&0xff) << 16) |
		(uint32(sum[offset+2]&0xff) << 8) |
		uint32(sum[offset+3]&0xff)
	return fmt.Sprintf("%06d", code%1000000), nil
}

// ComputeTOTPCode computes a 6-digit RFC 6238 TOTP code (HMAC-SHA1, 30-second window) for the given Base32 secret.
func ComputeTOTPCode(secret string, at time.Time) (string, error) {
	return ComputeTOTPCodeAtStep(secret, at.Unix()/30)
}

// MatchTOTPStep verifies a 6-digit TOTP code within ±1 30-second window and enforces monotonic step progression
// (matchedStep > lastStep) to prevent same-step and backward-step replay attacks.
func MatchTOTPStep(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	for i := 0; i < 6; i++ {
		if code[i] < '0' || code[i] > '9' {
			return 0, false
		}
	}
	baseStep := now.Unix() / 30
	var matchedStep int64
	matched := false
	for _, offset := range []int64{-1, 0, 1} {
		step := baseStep + offset
		expected, err := ComputeTOTPCodeAtStep(secret, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 && !matched {
			matchedStep = step
			matched = true
		}
	}
	if !matched || matchedStep <= lastStep {
		return 0, false
	}
	return matchedStep, true
}

// VerifyTOTPCode verifies a 6-digit TOTP code against the given Base32 secret within ±1 30-second window.
func VerifyTOTPCode(secret, code string, now time.Time) bool {
	_, ok := MatchTOTPStep(secret, code, now, 0)
	return ok
}

// verifyAndConsumeUserTOTP verifies code against user.TOTPSecret and atomically advances last_totp_step in the DB
// so concurrent or repeated submissions of the same (or older) 30-second TOTP step are strictly rejected.
func (s *Server) verifyAndConsumeUserTOTP(user *model.User, code string, now time.Time, extraUpdates map[string]any) bool {
	step, ok := MatchTOTPStep(user.TOTPSecret, code, now, user.LastTOTPStep)
	if !ok {
		return false
	}
	updates := map[string]any{
		"last_totp_step": step,
	}
	for k, v := range extraUpdates {
		updates[k] = v
	}
	res := s.db.Model(&model.User{}).
		Where("id = ? AND last_totp_step < ?", user.ID, step).
		Updates(updates)
	if res.Error != nil || res.RowsAffected != 1 {
		return false
	}
	user.LastTOTPStep = step
	return true
}

func (s *Server) handleSetupTOTP(c *gin.Context) {
	uid := s.currentUserID(c)
	var user model.User
	if err := s.db.First(&user, uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	if user.TOTPEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "当前账号已开启双因素认证 (2FA)，请先关闭后再重新设置"})
		return
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成 2FA 密钥失败"})
		return
	}
	res := s.db.Model(&model.User{}).
		Where("id = ? AND totp_enabled = ?", user.ID, false).
		Updates(map[string]any{
			"totp_secret":  secret,
			"totp_enabled": false,
		})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存 2FA 密钥失败"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "当前账号已开启双因素认证 (2FA)，请先关闭后再重新设置"})
		return
	}
	cfg := s.getSystemConfig()
	issuer := strings.TrimSpace(cfg.SiteName)
	if issuer == "" {
		issuer = "Zachary Panel"
	}
	otpauthURL := fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer),
		url.PathEscape(user.Email),
		url.QueryEscape(secret),
		url.QueryEscape(issuer),
	)
	c.JSON(http.StatusOK, gin.H{
		"secret":      secret,
		"otpauth_url": otpauthURL,
	})
}

func (s *Server) handleEnableTOTP(c *gin.Context) {
	uid := s.currentUserID(c)
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入 6 位动态验证码"})
		return
	}
	var user model.User
	if err := s.db.First(&user, uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	if user.TOTPEnabled {
		c.JSON(http.StatusConflict, gin.H{"error": "当前账号已启用双因素认证 (2FA)"})
		return
	}
	if strings.TrimSpace(user.TOTPSecret) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请先初始化生成 2FA 密钥"})
		return
	}
	email := normalizeEmail(user.Email)
	clientIP := c.ClientIP()
	if accountGuard.locked(email, clientIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "验证失败次数过多，请稍后再试"})
		return
	}
	if !s.verifyAndConsumeUserTOTP(&user, req.Code, time.Now(), map[string]any{
		"totp_enabled":  true,
		"token_version": gorm.Expr("token_version + 1"),
	}) {
		accountGuard.fail(email, clientIP)
		c.JSON(http.StatusBadRequest, gin.H{"error": "6 位动态验证码校验失败或已使用，请等待下一个 30 秒周期后重试"})
		return
	}
	_ = s.db.First(&user, user.ID).Error
	newToken, _ := GenerateToken(&user)
	if newToken != "" {
		c.Header("X-Renewed-Token", newToken)
	}
	s.recordAuditForUser(c, user.ID, user.Email, "user.totp_enable", user.Email, "启用 TOTP 双因素认证 (2FA) 并轮换会话令牌")
	c.JSON(http.StatusOK, gin.H{
		"message":      "双因素认证 (2FA) 已成功启用",
		"totp_enabled": true,
		"token":        newToken,
	})
}

func (s *Server) handleDisableTOTP(c *gin.Context) {
	uid := s.currentUserID(c)
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !bindOptionalJSON(c, &req) {
		return
	}
	var user model.User
	if err := s.db.First(&user, uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	if !user.TOTPEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "当前账号未启用双因素认证"})
		return
	}
	email := normalizeEmail(user.Email)
	clientIP := c.ClientIP()
	if accountGuard.locked(email, clientIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "验证失败次数过多，请稍后再试"})
		return
	}

	verified := false
	if strings.TrimSpace(req.Code) != "" {
		if s.verifyAndConsumeUserTOTP(&user, req.Code, time.Now(), map[string]any{
			"totp_enabled": false,
			"totp_secret":  "",
		}) {
			verified = true
		}
	}
	if !verified && req.Password != "" && len(req.Password) <= 1024 &&
		bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) == nil {
		s.db.Model(&model.User{}).Where("id = ?", user.ID).Updates(map[string]any{
			"totp_enabled": false,
			"totp_secret":  "",
		})
		verified = true
	}
	if !verified {
		accountGuard.fail(email, clientIP)
		c.JSON(http.StatusForbidden, gin.H{"error": "请提供正确的当前密码或未使用的 6 位 2FA 动态验证码以关闭双因素认证"})
		return
	}
	s.recordAuditForUser(c, user.ID, user.Email, "user.totp_disable", user.Email, "关闭 TOTP 双因素认证 (2FA)")
	c.JSON(http.StatusOK, gin.H{
		"message":      "双因素认证 (2FA) 已关闭",
		"totp_enabled": false,
	})
}

func hashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func (s *Server) handleAdminGenerateAPIKey(c *gin.Context) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成 API Key 失败"})
		return
	}
	rawKey := "zp_live_" + hex.EncodeToString(b)
	prefix := rawKey[:14] + "..."

	cfg := s.getSystemConfig()
	cfg.AdminAPIKeyHash = hashAPIKey(rawKey)
	cfg.AdminAPIKeyPrefix = prefix
	s.db.Save(&cfg)

	s.recordAudit(c, "admin.generate_api_key", prefix, "生成或轮换外部对接管理 API Key")
	c.JSON(http.StatusOK, gin.H{
		"api_key":              rawKey,
		"admin_api_key_prefix": prefix,
		"message":              "管理 API Key 已生成，请立即复制保存（完整密钥仅显示一次）",
	})
}

func (s *Server) handleAdminRevokeAPIKey(c *gin.Context) {
	cfg := s.getSystemConfig()
	oldPrefix := cfg.AdminAPIKeyPrefix
	cfg.AdminAPIKeyHash = ""
	cfg.AdminAPIKeyPrefix = ""
	s.db.Save(&cfg)

	s.recordAudit(c, "admin.revoke_api_key", oldPrefix, "吊销外部对接管理 API Key")
	c.JSON(http.StatusOK, gin.H{
		"message": "管理 API Key 已吊销",
	})
}
