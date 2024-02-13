use std::env;

use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::{AuthError, AuthResult, AuthUser};

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub user_id: String,
    pub    email: String,
    pub exp: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JWTResp {
    pub jwt: String,
}

#[derive(Debug)]
pub struct JWT {
    pub claims: Claims,
}

pub fn create_jwt(user: &AuthUser) -> AuthResult<String> {
    let secret: String = env::var("JWT_SECRET").expect("JWT_SECRET must be set.");

    // 👇 New!
    let expiration: i64 = Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("Invalid timestamp")
        .timestamp();

    let claims: Claims = Claims {
        user_id: user.user_id.to_owned(),
        email: user.email.to_owned(),
        exp: expiration as usize,
    };

    // 👇 New!
    let header = Header::new(Algorithm::HS512);

    match encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    ) {
        Ok(jwt) => Ok(jwt),
        Err(err) => Err(AuthError::JWTError(err.to_string())),
    }
}

pub fn decode_jwt(token: String) -> AuthResult<Claims> {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set.");
    let token = token.trim_start_matches("Bearer").trim();

    // 👇 New!
    match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS512),
    ) {
        Ok(token) => Ok(token.claims),
        Err(err) => Err(AuthError::JWTError(err.to_string())),
    }
}
