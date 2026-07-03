use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use zachary_panel_common::JwtClaims;

pub fn create_token(
    user_id: i64,
    username: &str,
    role: &str,
    secret: &str,
    expiry_hours: u64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now();
    let claims = JwtClaims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role: role.to_string(),
        iat: now.timestamp() as usize,
        exp: (now + chrono::Duration::hours(expiry_hours as i64)).timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

pub fn verify_token(token: &str, secret: &str) -> Result<JwtClaims, jsonwebtoken::errors::Error> {
    let token_data = decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}
