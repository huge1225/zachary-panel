package main

import (
	"flag"
	"log"
	"os"
	"time"

	"nexus-panel/internal/master/api"
	"nexus-panel/internal/master/hub"
	"nexus-panel/internal/master/model"
	"nexus-panel/internal/master/service"
)

func main() {
	var (
		listenAddr = flag.String("listen", getEnv("NEXUS_LISTEN", ":8080"), "HTTP/WebSocket listen address")
		dbDriver   = flag.String("db-driver", getEnv("NEXUS_DB_DRIVER", "sqlite"), "Database driver: sqlite | postgres | mysql")
		dbDSN      = flag.String("db-dsn", getEnv("NEXUS_DB_DSN", "nexus_panel.db"), "Database DSN connection string")
	)
	flag.Parse()

	db, err := model.InitDB(*dbDriver, *dbDSN)
	if err != nil {
		log.Fatalf("[Master] Database initialization failed: %v", err)
	}

	// Reset node status on Master cold start; connected Agents will re-register within 3s and auto-sync all rules
	db.Model(&model.Node{}).Where("status = ?", "online").Update("status", "offline")

	agentHub := hub.NewAgentHub(db)
	orch := service.NewOrchestrator(db, agentHub)

	// Start periodic 60s background quota cutoff & full state reconciliation scheduler
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			var expiredUsers []model.User
			db.Where("used_bytes >= quota_bytes OR expire_at < ?", time.Now()).Find(&expiredUsers)
			for _, u := range expiredUsers {
				orch.EnforceUserQuotaCutoff(u.ID)
			}
			orch.ReconcileAllOnlineNodes()
		}
	}()

	srv := api.NewServer(db, agentHub, orch)
	router := srv.SetupRouter()
	// Expose ONLY install-agent.sh, preventing directory listing or leakage of deploy/docker-compose.yml
	router.StaticFile("/deploy/install-agent.sh", "./deploy/install-agent.sh")

	log.Printf("[Master] Nexus Forwarding Panel listening on %s (DB=%s)", *listenAddr, *dbDriver)
	log.Printf("[Master] Default Admin Account: admin@nexus.local / admin123")
	if err := router.Run(*listenAddr); err != nil {
		log.Fatalf("[Master] Server exited: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
