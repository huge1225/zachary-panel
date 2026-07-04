//! 密码哈希工具

/// 使用 bcrypt 哈希密码
pub fn hash_password(password: &str) -> Result<String, anyhow::Error> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| anyhow::anyhow!("Password hash error: {e}"))
}

/// 验证 bcrypt 密码
pub fn verify_password(password: &str, hashed: &str) -> Result<bool, anyhow::Error> {
    bcrypt::verify(password, hashed).map_err(|e| anyhow::anyhow!("Password verify error: {e}"))
}

/// SHA256 哈希
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

/// HMAC-SHA256 签名
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

/// 生成随机十六进制字符串
pub fn random_hex(len: usize) -> String {
    use rand::Rng;
    let bytes: Vec<u8> = (0..len).map(|_| rand::thread_rng().gen()).collect();
    hex::encode(&bytes)[..len].to_string()
}

/// node_token 生成: nt_ + 64位hex
pub fn generate_node_token() -> String {
    format!("nt_{}", random_hex(64))
}

/// install_token 生成: it_ + 32位hex
pub fn generate_install_token() -> String {
    format!("it_{}", random_hex(32))
}
