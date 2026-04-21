package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/huge1225/zachary-panel/backend/internal/db"
)

type Server struct {
	db *db.DB
	r  *gin.Engine
}

func NewServer(d *db.DB) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	s := &Server{db: d, r: r}
	s.routes()
	return s
}

func (s *Server) routes() {
	api := s.r.Group("/api/v1")
	{
		// Agent 管理
		api.GET("/agents", s.listAgents)
		api.GET("/agents/:id", s.getAgent)
		api.POST("/agents", s.createAgent)
		api.DELETE("/agents/:id", s.deleteAgent)

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
	c.JSON(http.StatusCreated, rule)
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
