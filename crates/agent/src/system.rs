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

// ═══════════════════════════════════════════════════════════════
// VPS 监控数据采集
// ═══════════════════════════════════════════════════════════════

/// CPU 使用率（%）— 读取 /proc/stat 两次取差值
pub fn collect_cpu_usage() -> f64 {
    // 读取两次 /proc/stat 取差值计算 CPU 使用率
    let first = read_cpu_jiffies();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let second = read_cpu_jiffies();

    match (first, second) {
        (Some(f), Some(s)) => {
            let total_diff = s.total.saturating_sub(f.total);
            let idle_diff = s.idle.saturating_sub(f.idle);
            if total_diff == 0 {
                return 0.0;
            }
            let usage = (1.0 - (idle_diff as f64 / total_diff as f64)) * 100.0;
            usage.clamp(0.0, 100.0)
        }
        _ => {
            // fallback: sysinfo
            let mut sys = sysinfo::System::new();
            sys.refresh_cpu_usage();
            sys.global_cpu_usage() as f64
        }
    }
}

struct CpuJiffies {
    total: u64,
    idle: u64,
}

fn read_cpu_jiffies() -> Option<CpuJiffies> {
    let content = std::fs::read_to_string("/proc/stat").ok()?;
    let first_line = content.lines().next()?;
    // 格式: cpu  user nice system idle iowait irq softirq steal guest guest_nice
    let fields: Vec<&str> = first_line.split_whitespace().collect();
    if fields.len() < 5 {
        return None;
    }
    let user: u64 = fields[1].parse().ok()?;
    let nice: u64 = fields[2].parse().ok()?;
    let system: u64 = fields[3].parse().ok()?;
    let idle: u64 = fields[4].parse().ok()?;
    let iowait: u64 = fields.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
    let irq: u64 = fields.get(6).and_then(|s| s.parse().ok()).unwrap_or(0);
    let softirq: u64 = fields.get(7).and_then(|s| s.parse().ok()).unwrap_or(0);
    let steal: u64 = fields.get(8).and_then(|s| s.parse().ok()).unwrap_or(0);

    let total = user + nice + system + idle + iowait + irq + softirq + steal;
    Some(CpuJiffies { total, idle })
}

/// CPU 核心数
pub fn collect_cpu_cores() -> usize {
    let sys = sysinfo::System::new();
    sys.physical_core_count().unwrap_or_else(|| {
        let mut sys = sysinfo::System::new();
        sys.refresh_cpu_usage();
        sys.cpus().len()
    })
}

/// 磁盘使用 (used_gb, total_gb) — statvfs("/")
pub fn collect_disk_usage() -> (f64, f64) {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        let path = CString::new("/").unwrap();
        unsafe {
            let mut statvfs: libc_statvfs = std::mem::zeroed();
            if statvfs_syscall(path.as_ptr(), &mut statvfs) == 0 {
                let block_size = statvfs.f_frsize as f64;
                let total = statvfs.f_blocks as f64 * block_size;
                let avail = statvfs.f_bavail as f64 * block_size;
                let used = total - avail;
                return (used / 1e9, total / 1e9);
            }
        }
    }
    // fallback
    (0.0, 0.0)
}

/// 网络流量 (rx_bytes, tx_bytes) — 读取 /proc/net/dev 累计值
pub fn collect_network_stats() -> (u64, u64) {
    let content = match std::fs::read_to_string("/proc/net/dev") {
        Ok(c) => c,
        Err(_) => return (0, 0),
    };
    let mut total_rx: u64 = 0;
    let mut total_tx: u64 = 0;
    for line in content.lines().skip(2) {
        // 格式: iface: rx_bytes rx_packets ... tx_bytes tx_packets ...
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 2 {
            continue;
        }
        // 跳过 lo 接口
        let iface = parts[0].trim();
        if iface == "lo" {
            continue;
        }
        let stats: Vec<&str> = parts[1].split_whitespace().collect();
        if stats.len() < 16 {
            continue;
        }
        let rx: u64 = stats[0].parse().unwrap_or(0);
        let tx: u64 = stats[8].parse().unwrap_or(0);
        total_rx += rx;
        total_tx += tx;
    }
    (total_rx, total_tx)
}

/// Swap (used_mb, total_mb) — 读取 /proc/meminfo
pub fn collect_swap() -> (u64, u64) {
    let content = match std::fs::read_to_string("/proc/meminfo") {
        Ok(c) => c,
        Err(_) => return (0, 0),
    };
    let mut swap_total_kb: u64 = 0;
    let mut swap_free_kb: u64 = 0;
    for line in content.lines() {
        if line.starts_with("SwapTotal:") {
            swap_total_kb = line
                .split(':')
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
        } else if line.starts_with("SwapFree:") {
            swap_free_kb = line
                .split(':')
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }
    let used_mb = swap_total_kb.saturating_sub(swap_free_kb) / 1024;
    let total_mb = swap_total_kb / 1024;
    (used_mb, total_mb)
}

/// 主机名
pub fn collect_hostname() -> Option<String> {
    sysinfo::System::host_name()
}

/// 内核版本
pub fn collect_kernel() -> Option<String> {
    sysinfo::System::kernel_version()
}

// ═══════════════════════════════════════════════════════════════
// libc statvfs 绑定（避免额外依赖）
// ═══════════════════════════════════════════════════════════════

#[cfg(target_os = "linux")]
#[repr(C)]
struct libc_statvfs {
    f_bsize: u64,
    f_frsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_favail: u64,
    f_fsid: u64,
    f_flag: u64,
    f_namemax: u64,
    f_spare: [u64; 6],
}

#[cfg(target_os = "linux")]
extern "C" {
    fn statvfs(path: *const std::os::raw::c_char, buf: *mut libc_statvfs) -> i32;
}

#[cfg(target_os = "linux")]
fn statvfs_syscall(path: *const std::os::raw::c_char, buf: *mut libc_statvfs) -> i32 {
    unsafe { statvfs(path, buf) }
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
    match std::process::Command::new(gost_path).arg("-V").output() {
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
