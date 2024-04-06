use std::env;

use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use serde::{Deserialize, Serialize};

use crate::{AuthError, AuthResult, AuthUser};

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub user_id: String,
    pub email: String,
    pub exp: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JWTResp {
    pub jwt: String,
}

#[derive(Debug)]
pub struct Jwt {
    pub claims: Claims,
}

// impl<'r> FromRequest<'r> for Jwt {
//     type Error = AuthError;

//     async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
//         fn is_valid(key: &str) -> AuthResult<Claims> {
//             Ok(decode_jwt(String::from(key))?)
//         }

//         match req.headers().get_one("Authorization") {
//             None => Outcome::Error((
//                 Status::Unauthorized,
//                 AuthError::JWTError(format!("authorization header missing")),
//             )),
//             Some(key) => match is_valid(key) {
//                 Ok(claims) => Outcome::Success(Jwt { claims }),
//                 Err(err) => Outcome::Error((Status::Unauthorized, err)),
//             },
//         }
//     }
// }

fn secret() -> AuthResult<String> {
    match env::var("JWT_SECRET") {
        Ok(secret) => Ok(secret),
        Err(_) => return Err(AuthError::JWTError(format!("secret error"))),
    }
}

pub fn create_jwt(user: &AuthUser) -> AuthResult<String> {
    let secret: String = secret()?;

    let expiration: i64 = match Utc::now().checked_add_signed(chrono::Duration::hours(24)) {
        Some(d) => d.timestamp(),
        None => return Err(AuthError::JWTError(format!("invalid time"))),
    };

    let claims: Claims = Claims {
        user_id: user.user_id.to_owned(),
        email: user.email.to_owned(),
        exp: expiration as usize,
    };

    let header = Header::new(Algorithm::HS512);

    match encode(
        &header,
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    ) {
        Ok(jwt) => Ok(jwt),
        Err(_) => Err(AuthError::JWTError(format!("error encoding jwt"))),
    }
}

pub fn decode_jwt(token: String) -> AuthResult<Claims> {
    let secret: String = secret()?;

    let token: &str = token.trim_start_matches("Bearer").trim();

    // 👇 New!
    match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS512),
    ) {
        Ok(token) => Ok(token.claims),
        Err(err) => match &err.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                Err(AuthError::JWTError(format!("invalid jwt signature")))
            }
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                Err(AuthError::JWTError(format!("expired jwt token")))
            }
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                Err(AuthError::JWTError(format!("invalid jwt token")))
            }
            _ => Err(AuthError::JWTError(format!("{}", err))),
        },
    }
}
