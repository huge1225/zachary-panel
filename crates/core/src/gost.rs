//! gost 命令生成模块

use zachary_panel_common::{ForwardProtocol, TunnelType};

pub struct GostCommand {
    gost_path: String,
}

impl Default for GostCommand {
    fn default() -> Self {
        Self {
            gost_path: "/usr/local/bin/gost".into(),
        }
    }
}

impl GostCommand {
    pub fn new(gost_path: &str) -> Self {
        Self {
            gost_path: gost_path.to_string(),
        }
    }

    pub fn tcp_forward(
        &self,
        listen_port: i32,
        target_addr: &str,
        target_port: i32,
    ) -> Vec<String> {
        let url = format!("tcp://:{listen_port}/{target_addr}:{target_port}");
        vec![self.gost_path.clone(), "-L".into(), url]
    }

    pub fn udp_forward(
        &self,
        listen_port: i32,
        target_addr: &str,
        target_port: i32,
    ) -> Vec<String> {
        let url = format!("udp://:{listen_port}/{target_addr}:{target_port}");
        vec![self.gost_path.clone(), "-L".into(), url]
    }

    pub fn tcp_udp_forward(
        &self,
        listen_port: i32,
        target_addr: &str,
        target_port: i32,
    ) -> Vec<String> {
        let tcp = format!("tcp://:{listen_port}/{target_addr}:{target_port}");
        let udp = format!("udp://:{listen_port}/{target_addr}:{target_port}");
        vec![self.gost_path.clone(), "-L".into(), tcp, "-L".into(), udp]
    }

    pub fn ws_server(&self, listen_port: i32, ws_path: &str) -> Vec<String> {
        let url = format!("tcp+ws://:{listen_port}?path={ws_path}");
        vec![self.gost_path.clone(), "-L".into(), url]
    }

    pub fn wss_server(
        &self,
        listen_port: i32,
        ws_path: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Vec<String> {
        let url =
            format!("tcp+wss://:{listen_port}?path={ws_path}&cert={cert_path}&key={key_path}");
        vec![self.gost_path.clone(), "-L".into(), url]
    }

    pub fn ws_client(
        &self,
        listen_port: i32,
        target_addr: &str,
        target_port: i32,
        server_addr: &str,
        server_port: i32,
        ws_path: &str,
        tls: bool,
    ) -> Vec<String> {
        let scheme = if tls { "tcp+wss" } else { "tcp+ws" };
        let local = format!("rtcp://:{listen_port}/{target_addr}:{target_port}");
        let remote = format!("{scheme}://{server_addr}:{server_port}?path={ws_path}");
        vec![
            self.gost_path.clone(),
            "-L".into(),
            local,
            "-F".into(),
            remote,
        ]
    }

    pub fn generate_forward(
        &self,
        mode: &str,
        protocol: &ForwardProtocol,
        listen_port: i32,
        target_addr: &str,
        target_port: i32,
        tunnel_type: &TunnelType,
        ws_path: Option<&str>,
        cert_path: Option<&str>,
        key_path: Option<&str>,
        tls_skip_verify: bool,
    ) -> Result<Vec<String>, String> {
        match mode {
            "gost" => match tunnel_type {
                TunnelType::Plain => match protocol {
                    ForwardProtocol::Tcp => {
                        Ok(self.tcp_forward(listen_port, target_addr, target_port))
                    }
                    ForwardProtocol::Udp => {
                        Ok(self.udp_forward(listen_port, target_addr, target_port))
                    }
                    ForwardProtocol::TcpUdp => {
                        Ok(self.tcp_udp_forward(listen_port, target_addr, target_port))
                    }
                },
                TunnelType::Ws => {
                    let path = ws_path.unwrap_or("/ws");
                    Ok(self.ws_server(listen_port, path))
                }
                TunnelType::Wss => {
                    let path = ws_path.unwrap_or("/ws");
                    let cert = cert_path.ok_or("TLS cert path required")?;
                    let key = key_path.ok_or("TLS key path required")?;
                    let mut cmd = self.wss_server(listen_port, path, cert, key);
                    if tls_skip_verify {
                        if let Some(last) = cmd.last_mut() {
                            *last = format!("{last}&insecure=true");
                        }
                    }
                    Ok(cmd)
                }
            },
            _ => Err(format!("Unsupported mode: {mode}")),
        }
    }

    pub fn check_version(&self) -> Vec<String> {
        vec![self.gost_path.clone(), "-V".into()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_forward() {
        let g = GostCommand::default();
        let cmd = g.tcp_forward(8080, "10.0.0.5", 80);
        assert_eq!(cmd[1], "-L");
        assert!(cmd[2].contains("tcp://"));
    }
}
