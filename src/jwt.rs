use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sqlx::{Pool, Sqlite};

use crate::{email::Mailer, AuthError, AuthResult, User};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JwtClaims {
    pub uuid: String,
    pub exp: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JwtToken(pub JwtClaims);

#[derive(Clone)]
pub struct AppState {
    pub user_pool: Pool<Sqlite>,
    pub mailer: Mailer,
    pub secret: DecodingKey,
}

#[async_trait]
impl<S> FromRequestParts<S> for JwtToken
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
         let state = AppState::from_ref(state);

        let auth_header = parts.headers.get(AUTHORIZATION);

        let token = match auth_header {
            Some(header_value) => match header_value.to_str() {
                Ok(value) => match value.strip_prefix("Bearer ") {
                    Some(token) => token,
                    _ => {
                        return Err((StatusCode::UNAUTHORIZED, "bearer token missing".to_string()))
                    }
                },
                _ => return Err((StatusCode::UNAUTHORIZED, "bearer token missing".to_string())),
            },
            _ => return Err((StatusCode::UNAUTHORIZED, "bearer token missing".to_string())),
        };

        //&DecodingKey::from_secret(secret().as_bytes())

        match decode::<JwtClaims>(
            &token,
            &state.secret,
            &Validation::new(Algorithm::RS512),
        ) {
            Ok(data) => Ok(JwtToken(data.claims)),
            Err(err) => return Err((StatusCode::UNAUTHORIZED, err.to_string())),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JWTResp {
    pub token: String,
}

#[derive(Debug)]
pub struct Jwt {
    pub claims: JwtClaims,
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

pub fn secret() -> String {
    return sys::env::str("JWT_SECRET");
}

pub fn create_jwt(user: &User) -> AuthResult<String> {
    let secret: String = secret();

    let expiration: i64 = match Utc::now().checked_add_signed(chrono::Duration::hours(24)) {
        Some(d) => d.timestamp(),
        None => return Err(AuthError::JWTError(format!("invalid time"))),
    };

    let claims: JwtClaims = JwtClaims {
        uuid: user.uuid.to_owned(),

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

pub fn decode_jwt(token: String) -> AuthResult<JwtClaims> {
    let secret: String = secret();

    let token: &str = token.trim_start_matches("Bearer").trim();

    // 👇 New!
    match decode::<JwtClaims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::RS512),
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
