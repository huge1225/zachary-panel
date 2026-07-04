use sqlx::SqlitePool;

/// 运行所有迁移
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    create_users_table(pool).await?;
    create_nodes_table(pool).await?;
    create_forward_rules_table(pool).await?;
    create_tasks_table(pool).await?;
    create_traffic_stats_table(pool).await?;
    create_latency_tests_table(pool).await?;
    create_node_quality_stats_table(pool).await?;
    create_operation_logs_table(pool).await?;
    create_security_events_table(pool).await?;
    create_agent_nonces_table(pool).await?;
    migrate_v2(pool).await?;
    create_indexes(pool).await?;
    Ok(())
}

async fn create_users_table(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn create_nodes_table(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            node_token_hash TEXT NOT NULL,
            install_token_hash TEXT,
            install_token_expired_at TEXT,
            public_ip TEXT,
            os TEXT,
            arch TEXT,
            agent_version TEXT,
            agent_sha256 TEXT,
            gost_version TEXT,
            nft_status TEXT NOT NULL DEFAULT 'unknown',
            gost_status TEXT NOT NULL DEFAULT 'unknown',
            status TEXT NOT NULL DEFAULT 'offline',
            tls_verify INTEGER NOT NULL DEFAULT 1,
            tls_pinning INTEGER NOT NULL DEFAULT 0,
            pinned_cert_sha256 TEXT,
            last_signature_verified_at TEXT,
            last_heartbeat_at TEXT,
            last_task_at TEXT,
            last_ip TEXT,
            security_alerts TEXT NOT NULL DEFAULT '[]',
            remark TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn create_forward_rules_table(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS forward_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            node_id TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'nft',
            protocol TEXT NOT NULL DEFAULT 'tcp',
            listen_addr TEXT NOT NULL DEFAULT '0.0.0.0',
            listen_port INTEGER NOT NULL,
            target_addr TEXT NOT NULL,
            target_port INTEGER NOT NULL,
            tunnel_type TEXT NOT NULL DEFAULT 'plain',
            ws_path TEXT,
            tls_cert_path TEXT,
            tls_key_path TEXT,
            tls_skip_verify INTEGER NOT NULL DEFAULT 0,
            auth_type TEXT,
            auth_username TEXT,
            auth_password_encrypted TEXT,
            auth_token_encrypted TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'stopped',
            remark TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn create_tasks_table(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT NOT NULL UNIQUE,
            node_id TEXT NOT NULL,
            type TEXT NOT NULL,
            payload TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'pending',
            stdout TEXT,
            stderr TEXT,
            exit_code INTEGER,
            message TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            started_at TEXT,
            finished_at TEXT,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn create_traffic_stats_table(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id INTEGER NOT NULL,
            node_id TEXT NOT NULL,
            bytes_in INTEGER NOT NULL DEFAULT 0,
            bytes_out INTEGER NOT NULL DEFAULT 0,
            packets_in INTEGER NOT NULL DEFAULT 0,
            packets_out INTEGER NOT NULL DEFAULT 0,
            collected_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (rule_id) REFERENCES forward_rules(id) ON DELETE CASCADE,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn create_latency_tests_table(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS latency_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_id TEXT NOT NULL UNIQUE,
            node_id TEXT,
            rule_id INTEGER,
            test_type TEXT NOT NULL,
            target_addr TEXT NOT NULL,
            target_port INTEGER,
            count INTEGER NOT NULL DEFAULT 4,
            timeout_ms INTEGER NOT NULL DEFAULT 5000,
            interval_ms INTEGER NOT NULL DEFAULT 1000,
            success_count INTEGER NOT NULL DEFAULT 0,
            fail_count INTEGER NOT NULL DEFAULT 0,
            loss_rate REAL NOT NULL DEFAULT 0.0,
            min_latency_ms REAL,
            max_latency_ms REAL,
            avg_latency_ms REAL,
            jitter_ms REAL,
            http_status INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            error_message TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            started_at TEXT,
            finished_at TEXT,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE SET NULL,
            FOREIGN KEY (rule_id) REFERENCES forward_rules(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn create_node_quality_stats_table(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS node_quality_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            target_addr TEXT,
            target_port INTEGER,
            test_type TEXT NOT NULL DEFAULT 'icmp',
            avg_latency_ms REAL,
            loss_rate REAL NOT NULL DEFAULT 0.0,
            jitter_ms REAL,
            status TEXT NOT NULL DEFAULT 'unknown',
            collected_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn create_operation_logs_table(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS operation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            detail TEXT,
            ip TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn create_security_events_table(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            message TEXT NOT NULL,
            ip TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn create_agent_nonces_table(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS agent_nonces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            nonce TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expired_at TEXT NOT NULL,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// v2 增量迁移
async fn migrate_v2(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // "ALTER TABLE ADD COLUMN" 在 SQLite 中不支持 IF NOT EXISTS
    // 忽略错误即可（列已存在时返回 Err 但不影响）
    let migrations = [
        "ALTER TABLE forward_rules ADD COLUMN bytes_in INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE forward_rules ADD COLUMN bytes_out INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE forward_rules ADD COLUMN last_traffic_at TEXT",
        "ALTER TABLE forward_rules ADD COLUMN gost_service_name TEXT",
        "ALTER TABLE forward_rules ADD COLUMN traffic_ratio REAL NOT NULL DEFAULT 1.0",
        "ALTER TABLE nodes ADD COLUMN cpu_cores INTEGER",
        "ALTER TABLE nodes ADD COLUMN memory_total_mb INTEGER",
        "ALTER TABLE nodes ADD COLUMN load_avg TEXT",
    ];
    for sql in &migrations {
        let _ = sqlx::query(sql).execute(pool).await;
    }
    // v3 增量迁移：节点监控字段
    let v3_migrations = [
        "ALTER TABLE nodes ADD COLUMN cpu_usage REAL DEFAULT 0",
        "ALTER TABLE nodes ADD COLUMN disk_total_gb REAL",
        "ALTER TABLE nodes ADD COLUMN disk_used_gb REAL",
        "ALTER TABLE nodes ADD COLUMN network_rx_bytes INTEGER DEFAULT 0",
        "ALTER TABLE nodes ADD COLUMN network_tx_bytes INTEGER DEFAULT 0",
        "ALTER TABLE nodes ADD COLUMN swap_total_mb INTEGER DEFAULT 0",
        "ALTER TABLE nodes ADD COLUMN swap_used_mb INTEGER DEFAULT 0",
        "ALTER TABLE nodes ADD COLUMN kernel TEXT",
        "ALTER TABLE nodes ADD COLUMN hostname TEXT",
    ];
    for sql in &v3_migrations {
        let _ = sqlx::query(sql).execute(pool).await;
    }
    println!("v2+v3 migrations applied");
    Ok(())
}

async fn create_indexes(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // v2 migration: add traffic columns to forward_rules
    let _ = sqlx::query("ALTER TABLE forward_rules ADD COLUMN bytes_in INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ =
        sqlx::query("ALTER TABLE forward_rules ADD COLUMN bytes_out INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await;
    let _ = sqlx::query("ALTER TABLE forward_rules ADD COLUMN last_traffic_at TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE forward_rules ADD COLUMN gost_service_name TEXT")
        .execute(pool)
        .await;
    let _ =
        sqlx::query("ALTER TABLE forward_rules ADD COLUMN traffic_ratio REAL NOT NULL DEFAULT 1.0")
            .execute(pool)
            .await;
    // v2 migration: add last_ip columns to nodes
    let _ = sqlx::query("ALTER TABLE nodes ADD COLUMN cpu_cores INTEGER")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE nodes ADD COLUMN memory_total_mb INTEGER")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE nodes ADD COLUMN load_avg TEXT")
        .execute(pool)
        .await;

    let indexes = [
        "CREATE INDEX IF NOT EXISTS idx_nodes_node_id ON nodes(node_id)",
        "CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status)",
        "CREATE INDEX IF NOT EXISTS idx_forward_rules_node_id ON forward_rules(node_id)",
        "CREATE INDEX IF NOT EXISTS idx_forward_rules_status ON forward_rules(status)",
        "CREATE INDEX IF NOT EXISTS idx_tasks_task_id ON tasks(task_id)",
        "CREATE INDEX IF NOT EXISTS idx_tasks_node_id ON tasks(node_id)",
        "CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)",
        "CREATE INDEX IF NOT EXISTS idx_traffic_stats_rule_id ON traffic_stats(rule_id)",
        "CREATE INDEX IF NOT EXISTS idx_traffic_stats_collected_at ON traffic_stats(collected_at)",
        "CREATE INDEX IF NOT EXISTS idx_latency_tests_test_id ON latency_tests(test_id)",
        "CREATE INDEX IF NOT EXISTS idx_latency_tests_node_id ON latency_tests(node_id)",
        "CREATE INDEX IF NOT EXISTS idx_latency_tests_created_at ON latency_tests(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_node_quality_stats_node_id ON node_quality_stats(node_id)",
        "CREATE INDEX IF NOT EXISTS idx_operation_logs_created_at ON operation_logs(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_operation_logs_user_id ON operation_logs(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_node_id ON security_events(node_id)",
        "CREATE INDEX IF NOT EXISTS idx_agent_nonces_node_id ON agent_nonces(node_id)",
        "CREATE INDEX IF NOT EXISTS idx_agent_nonces_expired_at ON agent_nonces(expired_at)",
    ];

    for idx in &indexes {
        sqlx::query(idx).execute(pool).await?;
    }
    Ok(())
}
