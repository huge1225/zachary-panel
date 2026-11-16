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
	"nexus-panel/internal/master/model"
)

func generateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// ComputeTOTPCode computes a 6-digit RFC 6238 TOTP code (HMAC-SHA1, 30-second window) for the given Base32 secret.
func ComputeTOTPCode(secret string, at time.Time) (string, error) {
	clean := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		return "", err
	}
	counter := uint64(at.Unix() / 30)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

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

// VerifyTOTPCode verifies a 6-digit TOTP code against the given Base32 secret within ±1 30-second window.
func VerifyTOTPCode(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for _, step := range []int64{-1, 0, 1} {
		expected, err := ComputeTOTPCode(secret, now.Add(time.Duration(step*30)*time.Second))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
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
	if err := s.db.Model(&model.User{}).Where("id = ?", user.ID).Updates(map[string]any{
		"totp_secret":  secret,
		"totp_enabled": false,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存 2FA 密钥失败"})
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
	if strings.TrimSpace(user.TOTPSecret) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请先初始化生成 2FA 密钥"})
		return
	}
	if !VerifyTOTPCode(user.TOTPSecret, req.Code, time.Now()) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "6 位动态验证码校验失败，请确认验证器时间同步后重试"})
		return
	}
	s.db.Model(&model.User{}).Where("id = ?", user.ID).Update("totp_enabled", true)
	s.recordAuditForUser(c, user.ID, user.Email, "user.totp_enable", user.Email, "启用 TOTP 双因素认证 (2FA)")
	c.JSON(http.StatusOK, gin.H{
		"message":      "双因素认证 (2FA) 已成功启用",
		"totp_enabled": true,
	})
}

func (s *Server) handleDisableTOTP(c *gin.Context) {
	uid := s.currentUserID(c)
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	_ = c.ShouldBindJSON(&req)
	var user model.User
	if err := s.db.First(&user, uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	if !user.TOTPEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "当前账号未启用双因素认证"})
		return
	}
	verified := false
	if strings.TrimSpace(req.Code) != "" && VerifyTOTPCode(user.TOTPSecret, req.Code, time.Now()) {
		verified = true
	}
	if !verified && req.Password != "" && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) == nil {
		verified = true
	}
	if !verified {
		c.JSON(http.StatusForbidden, gin.H{"error": "请提供正确的当前密码或 6 位 2FA 动态验证码以关闭双因素认证"})
		return
	}
	s.db.Model(&model.User{}).Where("id = ?", user.ID).Updates(map[string]any{
		"totp_enabled": false,
		"totp_secret":  "",
	})
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
