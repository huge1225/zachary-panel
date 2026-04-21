package manager

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	pb "github.com/huge1225/zachary-panel/backend/internal/grpc"
	grpcPkg "github.com/huge1225/zachary-panel/backend/internal/grpc"
)

// GostManager gost管理器
type GostManager struct {
	rules map[string]*GostRule
	mu    sync.RWMutex
}

// GostRule gost规则
type GostRule struct {
	ID         string
	ListenAddr string
	TargetAddr string
	Protocol   string
	Enabled    bool
	cmd        *exec.Cmd
}

// NewGostManager 创建gost管理器
func NewGostManager() *GostManager {
	return &GostManager{
		rules: make(map[string]*GostRule),
	}
}

// AddRule 添加规则
func (gm *GostManager) AddRule(rule *pb.ForwardRule) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// 如果规则已存在，先停止
	if existing, exists := gm.rules[rule.Id]; exists {
		if existing.cmd != nil && existing.cmd.Process != nil {
			if err := existing.cmd.Process.Kill(); err != nil {
				log.Printf("Failed to kill existing rule %s: %v", rule.Id, err)
			}
		}
	}

	// 根据协议构建 gost 命令
	var gostCmd string
	switch rule.Protocol {
	case "tcp":
		gostCmd = fmt.Sprintf("gost -L tcp://%s -F tcp://%s", rule.ListenAddr, rule.TargetAddr)
	case "udp":
		gostCmd = fmt.Sprintf("gost -L udp://%s -F udp://%s", rule.ListenAddr, rule.TargetAddr)
	case "http":
		gostCmd = fmt.Sprintf("gost -L http://%s -F http://%s", rule.ListenAddr, rule.TargetAddr)
	case "https":
		gostCmd = fmt.Sprintf("gost -L https://%s -F https://%s", rule.ListenAddr, rule.TargetAddr)
	case "ws":
		gostCmd = fmt.Sprintf("gost -L ws://%s -F ws://%s", rule.ListenAddr, rule.TargetAddr)
	case "wss":
		gostCmd = fmt.Sprintf("gost -L wss://%s -F wss://%s", rule.ListenAddr, rule.TargetAddr)
	default:
		gostCmd = fmt.Sprintf("gost -L %s -F %s", rule.ListenAddr, rule.TargetAddr)
	}

	cmd := exec.Command("sh", "-c", gostCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start gost: %v", err)
	}

	gm.rules[rule.Id] = &GostRule{
		ID:         rule.Id,
		ListenAddr: rule.ListenAddr,
		TargetAddr: rule.TargetAddr,
		Protocol:   rule.Protocol,
		Enabled:    rule.Enabled,
		cmd:        cmd,
	}

	log.Printf("[gost] Started rule %s: %s -> %s (%s)", rule.Id, rule.ListenAddr, rule.TargetAddr, rule.Protocol)
	return nil
}

// RemoveRule 移除规则
func (gm *GostManager) RemoveRule(ruleID string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if rule, exists := gm.rules[ruleID]; exists {
		if rule.cmd != nil && rule.cmd.Process != nil {
			if err := rule.cmd.Process.Kill(); err != nil {
				log.Printf("Failed to kill rule %s: %v", ruleID, err)
			}
		}
		delete(gm.rules, ruleID)
		log.Printf("[gost] Removed rule: %s", ruleID)
	}
	return nil
}

// UpdateRule 更新规则
func (gm *GostManager) UpdateRule(rule *pb.ForwardRule) error {
	if err := gm.RemoveRule(rule.Id); err != nil {
		return err
	}
	return gm.AddRule(rule)
}

// GetRules 获取所有规则
func (gm *GostManager) GetRules() map[string]*GostRule {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	rules := make(map[string]*GostRule)
	for k, v := range gm.rules {
		rules[k] = v
	}
	return rules
}

// StopAll 停止所有规则
func (gm *GostManager) StopAll() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	for id, rule := range gm.rules {
		if rule.cmd != nil && rule.cmd.Process != nil {
			rule.cmd.Process.Kill()
		}
		delete(gm.rules, id)
		log.Printf("[gost] Stopped rule: %s", id)
	}
}

// NftManager nftables管理器
type NftManager struct {
	baseChain string
}

// NewNftManager 创建nftables管理器
func NewNftManager() *NftManager {
	return &NftManager{
		baseChain: "zachary_panel",
	}
}

// SetupBaseChain 设置基础链
func (nm *NftManager) SetupBaseChain() error {
	// 创建基础表（忽略已存在错误）
	exec.Command("sh", "-c", "nft add table ip zachary_panel").Run()

	// 创建基础链（忽略已存在错误）
	exec.Command("sh", "-c", `nft add chain ip zachary_panel forward { type filter hook forward priority 0 \; }`).Run()

	log.Println("[nft] Base chain ready")
	return nil
}

// AddRule 添加转发规则
func (nm *NftManager) AddRule(ruleID, listenAddr, targetAddr string) error {
	listenParts := strings.Split(listenAddr, ":")
	if len(listenParts) != 2 {
		return fmt.Errorf("invalid listen address: %s", listenAddr)
	}

	listenPort := listenParts[1]

	rule := fmt.Sprintf(`nft add rule ip zachary_panel forward tcp dport %s dnat to %s`,
		listenPort, targetAddr)

	cmd := exec.Command("sh", "-c", rule)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add nft rule: %v", err)
	}

	log.Printf("[nft] Added rule %s: port %s -> %s", ruleID, listenPort, targetAddr)
	return nil
}

// RemoveRule 移除转发规则
func (nm *NftManager) RemoveRule(ruleID string) error {
	// 清空并重建（简单实现，后续可以精细化）
	log.Printf("[nft] Removed rule: %s", ruleID)
	return nil
}

// FlushAll 清空所有 nft 规则
func (nm *NftManager) FlushAll() error {
	cmd := exec.Command("sh", "-c", "nft flush chain ip zachary_panel forward")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to flush nft rules: %v", err)
	}
	log.Println("[nft] Flushed all rules")
	return nil
}

// ConfigManager 配置管理器
type ConfigManager struct {
	gostMgr *GostManager
	nftMgr  *NftManager
}

// NewConfigManager 创建配置管理器
func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		gostMgr: NewGostManager(),
		nftMgr:  NewNftManager(),
	}
}

// ApplyConfig 应用配置
func (cm *ConfigManager) ApplyConfig(rules []*pb.ForwardRule) error {
	// 设置基础nftables链
	if err := cm.nftMgr.SetupBaseChain(); err != nil {
		return fmt.Errorf("failed to setup nftables: %v", err)
	}

	// 先清空旧的 nft 规则
	cm.nftMgr.FlushAll()

	// 应用每个规则
	for _, rule := range rules {
		if rule.Enabled {
			// 添加gost规则
			if err := cm.gostMgr.AddRule(rule); err != nil {
				log.Printf("Failed to add gost rule %s: %v", rule.Id, err)
				continue
			}

			// 添加nftables规则
			if err := cm.nftMgr.AddRule(rule.Id, rule.ListenAddr, rule.TargetAddr); err != nil {
				log.Printf("Failed to add nft rule %s: %v", rule.Id, err)
				continue
			}
		} else {
			// 禁用规则
			if err := cm.gostMgr.RemoveRule(rule.Id); err != nil {
				log.Printf("Failed to remove gost rule %s: %v", rule.Id, err)
			}
			if err := cm.nftMgr.RemoveRule(rule.Id); err != nil {
				log.Printf("Failed to remove nft rule %s: %v", rule.Id, err)
			}
		}
	}

	log.Printf("[config] Applied %d rules", len(rules))
	return nil
}

// StopAll 停止所有规则
func (cm *ConfigManager) StopAll() {
	cm.gostMgr.StopAll()
	cm.nftMgr.FlushAll()
}

// WatchConfigUpdates 监听配置更新并应用
func (cm *ConfigManager) WatchConfigUpdates(ctx context.Context, agent *grpcPkg.Agent) {
	for {
		select {
		case <-ctx.Done():
			return
		case config := <-agent.GetConfigChan():
			log.Printf("[config] Processing update: %d rules", len(config.Rules))
			if err := cm.ApplyConfig(config.Rules); err != nil {
			log.Printf("[config] Failed to apply: %v", err)
			}
		}
	}
}
