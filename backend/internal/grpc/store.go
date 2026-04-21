package grpc

import (
	"time"
)

// AgentStore Agent数据存储接口（由外部注入，避免循环依赖）
type AgentStore interface {
	GetAgent(id string) (*AgentInfo, error)
	GetRulesByAgent(agentID string) ([]ForwardRuleInfo, error)
	UpdateAgentStatus(id, status string) error
}

// AgentInfo Agent信息
type AgentInfo struct {
	ID        string
	Hostname  string
	IP        string
	OS        string
	Arch      string
	Status    string
	Token     string
	LastSeen  time.Time
	CreatedAt time.Time
}

// ForwardRuleInfo 转发规则信息
type ForwardRuleInfo struct {
	ID         string
	AgentID    string
	ListenAddr string
	TargetAddr string
	Protocol   string
	Enabled    bool
	Extra      string
	ConfigVer  string
}
