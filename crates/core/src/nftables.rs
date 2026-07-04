//! nftables 命令生成模块

use zachary_panel_common::ForwardProtocol;

pub struct NftCommand {
    nft_path: String,
    table: String,
    chain: String,
}

impl Default for NftCommand {
    fn default() -> Self {
        Self {
            nft_path: "/usr/sbin/nft".into(),
            table: "zachary-panel".into(),
            chain: "forward".into(),
        }
    }
}

impl NftCommand {
    pub fn new(nft_path: &str) -> Self {
        Self {
            nft_path: nft_path.to_string(),
            ..Default::default()
        }
    }

    pub fn init_table(&self) -> Vec<String> {
        args(&[&self.nft_path, "add", "table", "ip", &self.table])
    }

    pub fn init_chain(&self) -> Vec<String> {
        args(&[
            &self.nft_path,
            "add",
            "chain",
            "ip",
            &self.table,
            &self.chain,
            "{",
            "type",
            "nat",
            "hook",
            "prerouting",
            "priority",
            "dstnat",
            ";",
            "}",
        ])
    }

    pub fn add_tcp_forward(
        &self,
        public_ip: &str,
        listen_port: i32,
        target_addr: &str,
        target_port: i32,
    ) -> Vec<String> {
        let tgt = format!("{target_addr}:{target_port}");
        let port = listen_port.to_string();
        args(&[
            &self.nft_path,
            "add",
            "rule",
            "ip",
            &self.table,
            &self.chain,
            "ip",
            "daddr",
            public_ip,
            "tcp",
            "dport",
            &port,
            "counter",
            "dnat",
            "to",
            &tgt,
        ])
    }

    pub fn add_udp_forward(
        &self,
        public_ip: &str,
        listen_port: i32,
        target_addr: &str,
        target_port: i32,
    ) -> Vec<String> {
        let tgt = format!("{target_addr}:{target_port}");
        let port = listen_port.to_string();
        args(&[
            &self.nft_path,
            "add",
            "rule",
            "ip",
            &self.table,
            &self.chain,
            "ip",
            "daddr",
            public_ip,
            "udp",
            "dport",
            &port,
            "counter",
            "dnat",
            "to",
            &tgt,
        ])
    }

    pub fn add_forward(
        &self,
        protocol: &ForwardProtocol,
        public_ip: &str,
        listen_port: i32,
        target_addr: &str,
        target_port: i32,
    ) -> Vec<Vec<String>> {
        let mut cmds = Vec::new();
        if protocol.contains_tcp() {
            cmds.push(self.add_tcp_forward(public_ip, listen_port, target_addr, target_port));
        }
        if protocol.contains_udp() {
            cmds.push(self.add_udp_forward(public_ip, listen_port, target_addr, target_port));
        }
        cmds
    }

    pub fn flush_chain(&self) -> Vec<String> {
        args(&[
            &self.nft_path,
            "flush",
            "chain",
            "ip",
            &self.table,
            &self.chain,
        ])
    }

    /// 重载 zachary-panel 专属规则 — flush forward chain 后重新初始化
    /// 不触碰系统 /etc/nftables.conf
    pub fn reload_ruleset(&self) -> Vec<Vec<String>> {
        vec![
            self.flush_chain(),
            self.init_chain(),
        ]
    }

    pub fn list_rules(&self) -> Vec<String> {
        args(&[&self.nft_path, "list", "table", "ip", &self.table])
    }

    pub fn list_chain(&self) -> Vec<String> {
        args(&[
            &self.nft_path,
            "list",
            "chain",
            "ip",
            &self.table,
            &self.chain,
        ])
    }

    pub fn check_available(&self) -> Vec<String> {
        args(&[&self.nft_path, "--version"])
    }
}

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_forward() {
        let nft = NftCommand::default();
        let cmd = nft.add_tcp_forward("1.2.3.4", 8080, "10.0.0.5", 80);
        assert_eq!(cmd[0], "/usr/sbin/nft");
        assert!(cmd.contains(&"add".to_string()));
    }

    #[test]
    fn test_udp_forward() {
        let nft = NftCommand::default();
        let cmd = nft.add_udp_forward("1.2.3.4", 5353, "10.0.0.5", 53);
        assert!(cmd.contains(&"udp".to_string()));
    }
}
