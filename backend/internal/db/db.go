package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	*sql.DB
}

type Agent struct {
	ID        string
	Hostname  string
	IP        string
	OS        string
	Arch      string
	Status    string // online, offline
	Token     string
	LastSeen  time.Time
	CreatedAt time.Time
}

type ForwardRule struct {
	ID          string
	AgentID     string
	ListenAddr  string
	TargetAddr  string
	Protocol    string
	Enabled     bool
	Extra       string // JSON
	ConfigVer   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func Open(path string) (*DB, error) {
	d, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	if err := migrate(d); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &DB{d}, nil
}

func migrate(d *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS agents (
		id TEXT PRIMARY KEY,
		hostname TEXT NOT NULL,
		ip TEXT NOT NULL,
		os TEXT DEFAULT '',
		arch TEXT DEFAULT '',
		status TEXT DEFAULT 'offline',
		token TEXT NOT NULL UNIQUE,
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS forward_rules (
		id TEXT PRIMARY KEY,
		agent_id TEXT NOT NULL REFERENCES agents(id),
		listen_addr TEXT NOT NULL,
		target_addr TEXT NOT NULL,
		protocol TEXT DEFAULT 'tcp',
		enabled INTEGER DEFAULT 1,
		extra TEXT DEFAULT '{}',
		config_ver TEXT DEFAULT '1',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_rules_agent ON forward_rules(agent_id);
	`
	_, err := d.Exec(schema)
	return err
}

// Agent CRUD
func (d *DB) CreateAgent(a *Agent) error {
	_, err := d.Exec(`INSERT INTO agents (id, hostname, ip, os, arch, status, token, last_seen) VALUES (?,?,?,?,?,?,?,?)`,
		a.ID, a.Hostname, a.IP, a.OS, a.Arch, a.Status, a.Token, a.LastSeen)
	return err
}

func (d *DB) GetAgent(id string) (*Agent, error) {
	a := &Agent{}
	err := d.QueryRow(`SELECT id, hostname, ip, os, arch, status, token, last_seen, created_at FROM agents WHERE id=?`, id).
		Scan(&a.ID, &a.Hostname, &a.IP, &a.OS, &a.Arch, &a.Status, &a.Token, &a.LastSeen, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (d *DB) ListAgents() ([]Agent, error) {
	rows, err := d.Query(`SELECT id, hostname, ip, os, arch, status, last_seen, created_at FROM agents ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Hostname, &a.IP, &a.OS, &a.Arch, &a.Status, &a.LastSeen, &a.CreatedAt); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, nil
}

func (d *DB) UpdateAgentStatus(id, status string) error {
	_, err := d.Exec(`UPDATE agents SET status=?, last_seen=CURRENT_TIMESTAMP WHERE id=?`, status, id)
	return err
}

func (d *DB) DeleteAgent(id string) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	tx.Exec(`DELETE FROM forward_rules WHERE agent_id=?`, id)
	tx.Exec(`DELETE FROM agents WHERE id=?`, id)
	return tx.Commit()
}

// ForwardRule CRUD
func (d *DB) CreateRule(r *ForwardRule) error {
	_, err := d.Exec(`INSERT INTO forward_rules (id, agent_id, listen_addr, target_addr, protocol, enabled, extra, config_ver) VALUES (?,?,?,?,?,?,?,?)`,
		r.ID, r.AgentID, r.ListenAddr, r.TargetAddr, r.Protocol, r.Enabled, r.Extra, r.ConfigVer)
	return err
}

func (d *DB) GetRulesByAgent(agentID string) ([]ForwardRule, error) {
	rows, err := d.Query(`SELECT id, agent_id, listen_addr, target_addr, protocol, enabled, extra, config_ver, created_at, updated_at FROM forward_rules WHERE agent_id=?`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []ForwardRule
	for rows.Next() {
		var r ForwardRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.AgentID, &r.ListenAddr, &r.TargetAddr, &r.Protocol, &enabled, &r.Extra, &r.ConfigVer, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		rules = append(rules, r)
	}
	return rules, nil
}

func (d *DB) UpdateRule(r *ForwardRule) error {
	_, err := d.Exec(`UPDATE forward_rules SET listen_addr=?, target_addr=?, protocol=?, enabled=?, extra=?, config_ver=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		r.ListenAddr, r.TargetAddr, r.Protocol, r.Enabled, r.Extra, r.ConfigVer, r.ID)
	return err
}

func (d *DB) GetRule(id string) (*ForwardRule, error) {
	r := &ForwardRule{}
	var enabled int
	err := d.QueryRow(`SELECT id, agent_id, listen_addr, target_addr, protocol, enabled, extra, config_ver, created_at, updated_at FROM forward_rules WHERE id=?`, id).
		Scan(&r.ID, &r.AgentID, &r.ListenAddr, &r.TargetAddr, &r.Protocol, &enabled, &r.Extra, &r.ConfigVer, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	r.Enabled = enabled == 1
	return r, nil
}

func (d *DB) ListAllRules() ([]ForwardRule, error) {
	rows, err := d.Query(`SELECT id, agent_id, listen_addr, target_addr, protocol, enabled, extra, config_ver, created_at, updated_at FROM forward_rules ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []ForwardRule
	for rows.Next() {
		var r ForwardRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.AgentID, &r.ListenAddr, &r.TargetAddr, &r.Protocol, &enabled, &r.Extra, &r.ConfigVer, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		rules = append(rules, r)
	}
	return rules, nil
}

func (d *DB) DeleteRule(id string) error {
	_, err := d.Exec(`DELETE FROM forward_rules WHERE id=?`, id)
	return err
}
