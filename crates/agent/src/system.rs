/// 系统信息收集模块

use zachary_panel_common::SystemInfoPayload;

/// 收集系统信息
pub fn collect() -> SystemInfoPayload {
    // sysinfo 0.33: most info is via static methods
    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "unknown".into());
    let os = sysinfo::System::long_os_version().unwrap_or_else(|| "unknown".into());
    let kernel = sysinfo::System::kernel_version().unwrap_or_else(|| "unknown".into());
    let arch = std::env::consts::ARCH.to_string();

    let mut sys = sysinfo::System::new();
    sys.refresh_cpu_usage();
    sys.refresh_memory();

    let cpu_cores = sys.cpus().len();
    let memory_total_mb = sys.total_memory() / 1024 / 1024;
    let memory_used_mb = sys.used_memory() / 1024 / 1024;
    let uptime_seconds = sysinfo::System::uptime();

    // load_average returns LoadAvg
    let load = sysinfo::System::load_average();
    let load_avg = [load.one, load.five, load.fifteen];

    SystemInfoPayload {
        hostname,
        os,
        kernel,
        arch,
        cpu_cores,
        memory_total_mb,
        memory_used_mb,
        load_avg,
        uptime_seconds,
    }
}

/// 检测 nft 是否可用
pub fn nft_available(nft_path: &str) -> String {
    match std::process::Command::new(nft_path)
        .arg("--version")
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            } else {
                "unavailable".into()
            }
        }
        Err(_) => "not_found".into(),
    }
}

/// 检测 gost 是否可用
pub fn gost_available(gost_path: &str) -> String {
    match std::process::Command::new(gost_path)
        .arg("-V")
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            } else {
                "unavailable".into()
            }
        }
        Err(_) => "not_found".into(),
    }
}
