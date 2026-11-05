package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"nexus-panel/internal/agent/security"
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
		dataDir    = flag.String("data-dir", getEnv("NEXUS_DATA_DIR", ""), "Directory for persistent secrets (JWT key); defaults to the SQLite DB directory")
		staticDir  = flag.String("static-dir", getEnv("NEXUS_STATIC_DIR", "./deploy"), "Directory containing install-agent.sh and releases/ (agent binaries)")
		webDir     = flag.String("web-dir", getEnv("NEXUS_WEB_DIR", "./web/dist"), "Directory of the built frontend (index.html)")
		publicURL  = flag.String("public-url", getEnv("NEXUS_PUBLIC_URL", ""), "Externally reachable panel URL used in agent install commands, e.g. https://panel.example.com")
	)
	flag.Parse()
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	restrictUmask()
	if *dbDriver == "" || *dbDriver == "sqlite" {
		// Tighten permissions of a pre-existing database created before this hardening.
		if fi, err := os.Stat(*dbDSN); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o077 != 0 {
			if err := os.Chmod(*dbDSN, 0o600); err != nil {
				log.Printf("[Master] WARNING: could not restrict permissions of %s: %v", *dbDSN, err)
			}
		}
	}
	db, err := model.InitDB(*dbDriver, *dbDSN)
	if err != nil {
		log.Fatalf("[Master] Database initialization failed: %v", err)
	}

	api.SetJWTSecret(loadJWTSecret(resolveDataDir(*dataDir, *dbDriver, *dbDSN)))

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

	if *publicURL != "" && !strings.HasPrefix(*publicURL, "https://") {
		log.Printf("[Master] WARNING: NEXUS_PUBLIC_URL is not https; agent install commands and control channel will be unencrypted")
	}

	srv := api.NewServer(db, agentHub, orch)
	srv.SetStaticDir(*staticDir)
	srv.SetPublicURL(*publicURL)
	router := srv.SetupRouter()

	// Expose ONLY install-agent.sh and agent release binaries (no directory listing, no other deploy files).
	router.StaticFile("/deploy/install-agent.sh", filepath.Join(*staticDir, "install-agent.sh"))
	releasesDir := filepath.Join(*staticDir, "releases")
	router.GET("/deploy/releases/:file", func(c *gin.Context) {
		name := c.Param("file")
		if !strings.HasPrefix(name, "nexus-agent-linux-") || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
			c.Status(http.StatusNotFound)
			return
		}
		path := filepath.Join(releasesDir, name)
		fi, err := os.Stat(path)
		if err != nil || !fi.Mode().IsRegular() {
			c.Status(http.StatusNotFound)
			return
		}
		c.FileAttachment(path, name)
	})

	// Serve the built SPA (same origin as the API) with index.html fallback for client-side routes.
	serveSPA(router, *webDir)

	httpSrv := &http.Server{
		Addr:              *listenAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("[Master] Zachary Panel listening on %s (DB=%s)", *listenAddr, *dbDriver)
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("[Master] Server exited: %v", err)
	}
}

func serveSPA(router *gin.Engine, webDir string) {
	index := filepath.Join(webDir, "index.html")
	if _, err := os.Stat(index); err != nil {
		log.Printf("[Master] Frontend not found at %s (set NEXUS_WEB_DIR); only the API is served", webDir)
		return
	}
	absWeb, _ := filepath.Abs(webDir)
	router.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path
		if strings.HasPrefix(p, "/api/") || (c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		clean := filepath.Clean("/" + p)
		full := filepath.Join(absWeb, clean)
		if strings.HasPrefix(full, absWeb+string(os.PathSeparator)) {
			if fi, err := os.Stat(full); err == nil && fi.Mode().IsRegular() {
				c.File(full)
				return
			}
		}
		c.File(index)
	})
}

// resolveDataDir picks where persistent master secrets are stored.
func resolveDataDir(explicit, driver, dsn string) string {
	if explicit != "" {
		return explicit
	}
	if driver == "" || driver == "sqlite" {
		path := dsn
		if i := strings.Index(path, "?"); i >= 0 {
			path = path[:i]
		}
		path = strings.TrimPrefix(path, "file:")
		if dir := filepath.Dir(path); dir != "" {
			return dir
		}
	}
	return "."
}

// loadJWTSecret returns NEXUS_JWT_SECRET if set, otherwise loads (or creates) a persistent random key file so that
// restarts do not log every user out and no hard-coded key is ever used.
func loadJWTSecret(dataDir string) []byte {
	if env := strings.TrimSpace(os.Getenv("NEXUS_JWT_SECRET")); env != "" {
		if len(env) < 32 {
			log.Fatalf("[Master] NEXUS_JWT_SECRET must be at least 32 characters")
		}
		return []byte(env)
	}
	path := filepath.Join(dataDir, "jwt_secret.key")
	if data, err := os.ReadFile(path); err == nil {
		if key := strings.TrimSpace(string(data)); len(key) >= 32 {
			return []byte(key)
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("[Master] crypto/rand unavailable: %v", err)
	}
	key := hex.EncodeToString(b)
	if err := os.MkdirAll(dataDir, 0o700); err == nil {
		if err := security.WriteFileAtomic(path, []byte(key+"\n"), 0o600); err != nil {
			log.Printf("[Master] WARNING: could not persist JWT key to %s (%v); sessions will reset on restart", path, err)
		} else {
			log.Printf("[Master] Generated persistent JWT signing key at %s", path)
		}
	}
	return []byte(key)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
