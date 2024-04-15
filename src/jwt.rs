use std::fmt;

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
};

use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use serde::{Deserialize, Serialize};
 

use crate::{create_otp, email::Mailer, AuthError, AuthResult, User, UserDb};

pub const TOKEN_TYPE_REFRESH_TTL_HOURS: i64 = 24;
pub const TOKEN_TYPE_ACCESS_TTL_HOURS: i64 = 1;
pub const TOKEN_TYPE_SHORT_TIME_TTL_MINS: i64 = 10;

pub const TOKEN_PASSWORDLESS: &str = "passwordless";
pub const TOKEN_VERIFY_EMAIL: &str = "verify_email";
pub const TOKEN_RESET_PASSWORD: &str = "reset_password";



#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum TokenType {
    Refresh,
    Access,
    Passwordless,
    ResetPassword,
    VerifyEmail,
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TokenType::Refresh => write!(f, "refresh"),
            TokenType::Access => write!(f, "access"),
            TokenType::Passwordless => write!(f, "{}", TOKEN_PASSWORDLESS),
            TokenType::ResetPassword => write!(f, "{}", TOKEN_RESET_PASSWORD),
            TokenType::VerifyEmail => write!(f, "{}", TOKEN_VERIFY_EMAIL),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JwtClaims {
    pub uuid: String,
    pub token_type: String,
    pub otp: String,
    pub exp: usize,
}


#[derive(Clone)]
pub struct AppState {
    pub user_db: UserDb,
    pub mailer: Mailer,
    pub jwt_public_key: DecodingKey,
    pub jwt_private_key: EncodingKey
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JwtToken(pub JwtClaims);

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

        match decode::<JwtClaims>(&token, &state.jwt_public_key, &Validation::new(Algorithm::EdDSA)) {
            Ok(data) => Ok(JwtToken(data.claims)),
            Err(err) => return Err((StatusCode::UNAUTHORIZED, err.to_string())),
        }
    }
}

// #[derive(Debug, Deserialize, Serialize)]
// pub struct JWTResp {
//     pub token: String,
// }

// #[derive(Debug)]
// pub struct Jwt {
//     pub claims: JwtClaims,
// }

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

// pub fn secret() -> String {
//     return sys::env::str("JWT_SECRET");
// }

// pub fn create_jwt(user: &User) -> AuthResult<String> {
//     let secret: String = secret();

//     let expiration: i64 = match Utc::now().checked_add_signed(chrono::Duration::hours(24)) {
//         Some(d) => d.timestamp(),
//         None => return Err(AuthError::JWTError(format!("invalid time"))),
//     };

//     let claims: JwtClaims = JwtClaims {
//         uuid: user.uuid.to_owned(),
//         exp: expiration as usize,
//     };

//     let header = Header::new(Algorithm::HS512);

//     match encode(
//         &header,
//         &claims,
//         &EncodingKey::from_secret(secret.as_bytes()),
//     ) {
//         Ok(jwt) => Ok(jwt),
//         Err(_) => Err(AuthError::JWTError(format!("error encoding jwt"))),
//     }
// }

pub fn refresh_jwt(uuid: &str, key: &EncodingKey) -> AuthResult<String> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::hours(TOKEN_TYPE_REFRESH_TTL_HOURS))
        .expect("valid timestamp")
        .timestamp();

    eprint!("exp {}", expiration);

    jwt(uuid, &TokenType::Refresh, key, expiration)
}

pub fn access_jwt(uuid: &str, key: &EncodingKey) -> AuthResult<String> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::hours(TOKEN_TYPE_ACCESS_TTL_HOURS))
        .expect("valid timestamp")
        .timestamp();

    jwt(uuid, &TokenType::Access, key, expiration)
}

pub fn verify_email_jwt(uuid: &str, key: &EncodingKey) -> AuthResult<String> {
    short_jwt(uuid, &TokenType::VerifyEmail, key)
}

pub fn reset_password_jwt(user: &User, key: &EncodingKey) -> AuthResult<String> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(TOKEN_TYPE_SHORT_TIME_TTL_MINS))
        .expect("valid timestamp")
        .timestamp();

    let claims: JwtClaims = JwtClaims {
        uuid: user.uuid.to_string(),
        token_type: TokenType::ResetPassword.to_string(),
        otp: create_otp(user),
        exp: expiration as usize,
    };

    base_jwt(&claims, key)
}

pub fn passwordless_jwt(uuid: &str, key: &EncodingKey) -> AuthResult<String> {
    short_jwt(uuid, &TokenType::Passwordless, key)
}

pub fn otp_jwt(
    user: &User,
    token_type: &TokenType,
    key: &EncodingKey,
) -> AuthResult<String> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(TOKEN_TYPE_SHORT_TIME_TTL_MINS))
        .expect("valid timestamp")
        .timestamp();

    basic_jwt(
        &user.uuid,
        token_type,
        &create_otp(user),
        key,
        expiration,
    )
}

pub fn short_jwt(uuid: &str, token_type: &TokenType, key: &EncodingKey) -> AuthResult<String> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(TOKEN_TYPE_SHORT_TIME_TTL_MINS))
        .expect("valid timestamp")
        .timestamp();

    jwt(uuid, token_type, key, expiration)
}

pub fn jwt(
    uuid: &str,
    token_type: &TokenType,
    key: &EncodingKey,
    expiration: i64,
) -> AuthResult<String> {
    basic_jwt(uuid, token_type, "", key, expiration)
}

pub fn basic_jwt(
    uuid: &str,
    token_type: &TokenType,
    otp: &str,
    key: &EncodingKey,
    expiration: i64,
) -> AuthResult<String> {
    let claims: JwtClaims = JwtClaims {
        uuid: uuid.to_string(),
        token_type: token_type.to_string(),
        otp: otp.to_string(),
        exp: expiration as usize,
    };

    eprintln!("claims {}", claims.uuid);

    base_jwt(&claims, key)
}

pub fn base_jwt(claims: &JwtClaims, key: &EncodingKey) -> AuthResult<String> {
    let header = Header::new(Algorithm::EdDSA);

 
    match encode(&header, claims, key) {
        Ok(jwt) => Ok(jwt),
        Err(err) => Err(AuthError::TokenError(err.to_string())),
    }
}

pub fn decode_jwt(token: String, key: &DecodingKey) -> AuthResult<JwtClaims> {
 
    let token: &str = token.trim_start_matches("Bearer").trim();

    // 👇 New!
    match decode::<JwtClaims>(
        &token,
        key,
        &Validation::new(Algorithm::EdDSA),
    ) {
        Ok(token) => Ok(token.claims),
        Err(err) => match &err.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                Err(AuthError::TokenError(format!("invalid jwt signature")))
            }
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                Err(AuthError::TokenError(format!("expired jwt token")))
            }
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                Err(AuthError::TokenError(format!("invalid jwt token")))
            }
            _ => Err(AuthError::TokenError(format!("{}", err))),
        },
    }
}
