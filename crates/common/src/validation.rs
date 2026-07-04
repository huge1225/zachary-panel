//! 输入校验工具

/// 校验 IP 地址合法性
pub fn validate_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// 校验端口范围 (1-65535)
pub fn validate_port(port: i32) -> bool {
    (1..=65535).contains(&port)
}

/// 校验域名合法性
pub fn validate_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    // 允许 IP 地址也作为域名
    if validate_ip(host) {
        return true;
    }
    host.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !host.starts_with('-')
        && !host.ends_with('-')
}

/// 校验路径安全性（防止路径遍历）
pub fn validate_path(path: &str) -> bool {
    if path.is_empty() {
        return true; // 允许空路径
    }
    if path.contains("..") {
        return false;
    }
    if path.contains('\\') {
        return false;
    }
    // 只允许可打印的 ASCII + /
    path.chars()
        .all(|c| c.is_ascii_graphic() || c == '/' || c == ' ')
}

/// 校验节点名称
pub fn validate_node_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' || c as u32 > 127)
}

/// 校验字符串长度
pub fn validate_length(s: &str, min: usize, max: usize) -> bool {
    s.len() >= min && s.len() <= max
}
