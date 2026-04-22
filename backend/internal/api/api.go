package api

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/huge1225/zachary-panel/backend/internal/cert"
	"github.com/huge1225/zachary-panel/backend/internal/db"
	grpcPkg "github.com/huge1225/zachary-panel/backend/internal/grpc"
)

type Server struct {
	db      *db.DB
	r       *gin.Engine
	grpcSrv interface{}
}

func NewServer(d *db.DB) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	s := &Server{db: d, r: r}
	s.routes()
	return s
}

// SetGRPCServer 设置 gRPC 服务引用（用于推送配置）
func (s *Server) SetGRPCServer(grpcSrv interface{}) {
	s.grpcSrv = grpcSrv
}

func (s *Server) routes() {
	api := s.r.Group("/api/v1")
	{
		// Agent 管理
		api.GET("/agents", s.listAgents)
		api.GET("/agents/:id", s.getAgent)
		api.POST("/agents", s.createAgent)
		api.DELETE("/agents/:id", s.deleteAgent)
		api.GET("/agents/:id/certs.zip", s.getAgentCerts) // 新增

		// 转发规则
		api.GET("/agents/:id/rules", s.listRules)
		api.POST("/agents/:id/rules", s.createRule)
		api.PUT("/rules/:ruleId", s.updateRule)
		api.DELETE("/rules/:ruleId", s.deleteRule)

		// Dashboard
		api.GET("/dashboard", s.dashboard)
	}
}

func (s *Server) Run(addr string) error {
	return s.r.Run(addr)
}

// --- Handlers ---

func (s *Server) listAgents(c *gin.Context) {
	agents, err := s.db.ListAgents()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"agents": agents})
}

func (s *Server) getAgent(c *gin.Context) {
	agent, err := s.db.GetAgent(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	c.JSON(http.StatusOK, agent)
}

func (s *Server) deleteAgent(c *gin.Context) {
	if err := s.db.DeleteAgent(c.Param("id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (s *Server) listRules(c *gin.Context) {
	rules, err := s.db.GetRulesByAgent(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules})
}

func (s *Server) createRule(c *gin.Context) {
	var req struct {
		ListenAddr string `json:"listen_addr" binding:"required"`
		TargetAddr string `json:"target_addr" binding:"required"`
		Protocol   string `json:"protocol"`
		Extra      string `json:"extra"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	agentID := c.Param("id")
	rule := &db.ForwardRule{
		ID:         generateID(),
		AgentID:    agentID,
		ListenAddr: req.ListenAddr,
		TargetAddr: req.TargetAddr,
		Protocol:   defaultStr(req.Protocol, "tcp"),
		Enabled:    true,
		Extra:      defaultStr(req.Extra, "{}"),
		ConfigVer:  "1",
	}
	if err := s.db.CreateRule(rule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.pushRulesToAgent(agentID)
	c.JSON(http.StatusCreated, rule)
}

// pushRulesToAgent 推送规则给 Agent
func (s *Server) pushRulesToAgent(agentID string) {
	rules, _ := s.db.GetRulesByAgent(agentID)
	pbRules := make([]*grpcPkg.ForwardRule, len(rules))
	for i, r := range rules {
		pbRules[i] = &grpcPkg.ForwardRule{
			Id:         r.ID,
			AgentId:    r.AgentID,
			ListenAddr: r.ListenAddr,
			TargetAddr: r.TargetAddr,
			Protocol:   r.Protocol,
			Enabled:    r.Enabled,
			Extra:      r.Extra,
			ConfigVer:  r.ConfigVer,
		}
	}
	if grpcSrv, ok := s.grpcSrv.(interface {
		PushConfigToAgent(context.Context, *grpcPkg.PushConfigRequest) (*grpcPkg.PushConfigResponse, error)
	}); ok {
		grpcSrv.PushConfigToAgent(context.Background(), &grpcPkg.PushConfigRequest{
			AgentId:   agentID,
			Rules:     pbRules,
			ConfigVer: "1",
		})
	}
}

func (s *Server) updateRule(c *gin.Context) {
	ruleID := c.Param("ruleId")

	existing, err := s.db.GetRule(ruleID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	var req struct {
		ListenAddr *string `json:"listen_addr"`
		TargetAddr *string `json:"target_addr"`
		Protocol   *string `json:"protocol"`
		Enabled    *bool   `json:"enabled"`
		Extra      *string `json:"extra"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Merge
	if req.ListenAddr != nil {
		existing.ListenAddr = *req.ListenAddr
	}
	if req.TargetAddr != nil {
		existing.TargetAddr = *req.TargetAddr
	}
	if req.Protocol != nil {
		existing.Protocol = *req.Protocol
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.Extra != nil {
		existing.Extra = *req.Extra
	}

	if err := s.db.UpdateRule(existing); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.pushRulesToAgent(existing.AgentID)
	c.JSON(http.StatusOK, existing)
}

func (s *Server) deleteRule(c *gin.Context) {
	if err := s.db.DeleteRule(c.Param("ruleId")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (s *Server) createAgent(c *gin.Context) {
	var req struct {
		ID       string `json:"id" binding:"required"`
		Hostname string `json:"hostname" binding:"required"`
		IP       string `json:"ip" binding:"required"`
		Token    string `json:"token" binding:"required"`
		OS       string `json:"os"`
		Arch     string `json:"arch"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	agent := &db.Agent{
		ID:        req.ID,
		Hostname:  req.Hostname,
		IP:        req.IP,
		OS:        defaultStr(req.OS, "linux"),
		Arch:      defaultStr(req.Arch, "amd64"),
		Status:    "offline",
		Token:     req.Token,
		LastSeen:  time.Time{},
	}
	if err := s.db.CreateAgent(agent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, agent)
}

// getAgentCerts 获取 Agent 证书 ZIP
func (s *Server) getAgentCerts(c *gin.Context) {
	agentID := c.Param("id")
	if _, err := s.db.GetAgent(agentID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	// 获取 CA 和 Server 证书目录路径
	dataDir := envOrDefault("DATA_DIR", "/data")
	certDir := filepath.Join(dataDir, "certs")
	caDir := filepath.Join(certDir, "ca")
	agentCertDir := filepath.Join(certDir, "agents", agentID)

	// 确保 CA 存在
	if _, err := os.Stat(filepath.Join(caDir, "ca.crt")); os.IsNotExist(err) {
		if err := cert.GenerateCA(caDir); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	// 为 Agent 生成证书
	if err := cert.GenerateCert(caDir, agentCertDir, fmt.Sprintf("agent-%s", agentID)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 创建 ZIP
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// 添加文件
	files := []struct {
		local string
		zip   string
	}{
		{filepath.Join(agentCertDir, "ca.crt"), "ca.crt"},
		{filepath.Join(agentCertDir, "tls.crt"), "tls.crt"},
		{filepath.Join(agentCertDir, "tls.key"), "tls.key"},
	}

	for _, f := range files {
		content, err := os.ReadFile(f.local)
		if err != nil {
			continue // 不中断
		}
		fw, _ := w.Create(f.zip)
		fw.Write(content)
	}

	w.Close()

	// 响应
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=agent-%s-certs.zip", agentID))
	c.Data(http.StatusOK, "application/zip", buf.Bytes())
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func (s *Server) dashboard(c *gin.Context) {
	agents, _ := s.db.ListAgents()
	online := 0
	totalRules := 0
	activeRules := 0
	for _, a := range agents {
		if a.Status == "online" {
			online++
		}
		rules, _ := s.db.GetRulesByAgent(a.ID)
		totalRules += len(rules)
		for _, r := range rules {
			if r.Enabled {
				activeRules++
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"total_agents":  len(agents),
		"online_agents": online,
		"total_rules":   totalRules,
		"active_rules":  activeRules,
	})
}

func generateID() string {
	// 简单实现，后续用 UUID
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
