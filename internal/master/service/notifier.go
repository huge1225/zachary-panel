package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gorm.io/gorm"
	"nexus-panel/internal/agent/security"
	"nexus-panel/internal/master/model"
)

// Notifier dispatches operational alerts (node online/offline, node/user quota exhaustion, and test alerts)
// to configured Webhook URLs (Feishu / DingTalk / WeCom / Generic JSON) and Telegram Bot chats.
type Notifier struct {
	db         *gorm.DB
	httpClient *http.Client
}

func NewNotifier(db *gorm.DB) *Notifier {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return security.SafeDialTCP(ctx, addr, 5*time.Second, security.DefaultPolicy.AllowPrivateTargets)
		},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	return &Notifier{
		db: db,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   6 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (n *Notifier) loadConfig() model.SystemConfig {
	var cfg model.SystemConfig
	_ = n.db.First(&cfg, 1).Error
	return cfg
}

// ValidateWebhookURL checks that rawURL is a valid http/https URL and passes SSRF host validation.
func ValidateWebhookURL(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("Webhook 地址需为有效的 http:// 或 https:// URL")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(u.Hostname(), port)
	if err := security.ValidateTargetAddress(addr, security.DefaultPolicy.AllowPrivateTargets); err != nil {
		return fmt.Errorf("Webhook 目标地址未通过安全校验: %w", err)
	}
	return nil
}

// SendAlert delivers an alert to all configured channels (Webhook and/or Telegram Bot).
func (n *Notifier) SendAlert(event, title, message string) error {
	cfg := n.loadConfig()
	webhookURL := strings.TrimSpace(cfg.NotifyWebhookURL)
	tgToken := strings.TrimSpace(cfg.NotifyTelegramBotToken)
	tgChat := strings.TrimSpace(cfg.NotifyTelegramChatID)

	if webhookURL == "" && (tgToken == "" || tgChat == "") {
		return fmt.Errorf("尚未配置任何告警通道（Webhook URL 或 Telegram Bot）")
	}

	var firstErr error
	sent := 0
	fullText := fmt.Sprintf("🔔 【%s】 %s\n%s", cfg.SiteName, title, message)

	if webhookURL != "" {
		if err := ValidateWebhookURL(webhookURL); err != nil {
			firstErr = err
		} else {
			payload := map[string]any{
				"event":     event,
				"site_name": cfg.SiteName,
				"title":     title,
				"message":   message,
				"text":      fullText,
				"msg_type":  "text",
				"msgtype":   "text",
				"content":   map[string]string{"text": fullText},
				"timestamp": time.Now().Unix(),
			}
			if err := n.postJSON(webhookURL, payload); err != nil {
				firstErr = err
			} else {
				sent++
			}
		}
	}

	if tgToken != "" && tgChat != "" {
		tgURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", url.PathEscape(tgToken))
		payload := map[string]any{
			"chat_id": tgChat,
			"text":    fullText,
		}
		if err := n.postJSON(tgURL, payload); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			sent++
		}
	}

	if sent == 0 && firstErr != nil {
		return firstErr
	}
	return nil
}

func (n *Notifier) postJSON(targetURL string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "ZacharyPanel-Notifier/1.0")
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("通知接口返回 HTTP %d", resp.StatusCode)
	}
	return nil
}

// NotifyNodeEventAsync dispatches node online/offline alerts in the background if enabled.
func (n *Notifier) NotifyNodeEventAsync(event, title, message string) {
	if n == nil {
		return
	}
	cfg := n.loadConfig()
	if !cfg.NotifyOnNodeEvents {
		return
	}
	if strings.TrimSpace(cfg.NotifyWebhookURL) == "" &&
		(strings.TrimSpace(cfg.NotifyTelegramBotToken) == "" || strings.TrimSpace(cfg.NotifyTelegramChatID) == "") {
		return
	}
	go func() {
		_ = n.SendAlert(event, title, message)
	}()
}

// NotifyQuotaEventAsync dispatches node/user quota cutoff alerts in the background if enabled.
func (n *Notifier) NotifyQuotaEventAsync(event, title, message string) {
	if n == nil {
		return
	}
	cfg := n.loadConfig()
	if !cfg.NotifyOnQuotaEvents {
		return
	}
	if strings.TrimSpace(cfg.NotifyWebhookURL) == "" &&
		(strings.TrimSpace(cfg.NotifyTelegramBotToken) == "" || strings.TrimSpace(cfg.NotifyTelegramChatID) == "") {
		return
	}
	go func() {
		_ = n.SendAlert(event, title, message)
	}()
}
