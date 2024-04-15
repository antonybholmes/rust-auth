use std::fmt::{self, Display};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

use password_auth::{generate_hash, verify_password, VerifyError};
use rusty_paseto::generic::{GenericBuilderError, PasetoClaimError};
use sqlx::{FromRow, Pool, Sqlite};
use tokio::task::JoinError;
use uuid::Uuid;

use axum_login::AuthUser;
use serde::{Deserialize, Serialize};

pub mod email;
pub mod jwt;
pub mod paseto;
mod tests;

//const USER_SQL: &'static str = "SELECT id, uuid, first_name, last_name, username, email, password, strftime('%s', updated_on) as updated_on FROM users";

const FIND_USER_BY_UUID_SQL: &'static str = r#"SELECT
id, uuid, first_name, last_name, username, email, password, strftime('%s', updated_on) as updated_on, can_signin, email_verified
FROM users
WHERE users.uuid = $1 LIMIT 1"#;

const FIND_USER_BY_USERNAME_SQL: &'static str = r#"SELECT
id, uuid, first_name, last_name, username, email, password, strftime('%s', updated_on) as updated_on, can_signin, email_verified
FROM users
WHERE users.username = $1 LIMIT 1"#;

const FIND_USER_BY_EMAIL_SQL: &'static str = r#"SELECT
id, uuid, first_name, last_name, username, email, password, strftime('%s', updated_on) as updated_on, can_signin, email_verified
FROM users
WHERE users.email = $1 LIMIT 1"#;


const EMAIL_VERIFIED_SQL: &'static str =
    "UPDATE users SET email_verified = 1 WHERE users.uuid = $1";

const CREATE_USER_SQL: &'static str =
    "INSERT INTO users (uuid, username, email, password) VALUES($1, $2, $3, $4)";

#[derive(Debug, Clone)]
pub enum AuthError {
    UserDoesNotExistError(String),
    UserAlreadyExistsError(String),
    CouldNotCreateUserError(String),
    DatabaseError(String),
    CryptographyError(String),
    TokenError(String),
    PasswordError(String),
}

impl std::error::Error for AuthError {}

impl From<time::error::Format> for AuthError {
    fn from(error: time::error::Format) -> Self {
        AuthError::TokenError(error.to_string())
    }
}

impl From<PasetoClaimError> for AuthError {
    fn from(error: PasetoClaimError) -> Self {
        AuthError::TokenError(error.to_string())
    }
}

impl From<VerifyError> for AuthError {
    fn from(error: VerifyError) -> Self {
        AuthError::PasswordError(error.to_string())
    }
}

impl From<JoinError> for AuthError {
    fn from(error: JoinError) -> Self {
        AuthError::PasswordError(error.to_string())
    }
}

impl From<GenericBuilderError> for AuthError {
    fn from(error: GenericBuilderError) -> Self {
        AuthError::PasswordError(error.to_string())
    }
}

impl From<sqlx::Error> for AuthError {
    fn from(error: sqlx::Error) -> Self {
        AuthError::DatabaseError(error.to_string())
    }
}

//impl std::error::Error for AuthError {}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::UserDoesNotExistError(user) => {
                write!(f, "account for {} does not exist", user)
            }
            AuthError::UserAlreadyExistsError(user) => {
                write!(f, "acount for {} already exists", user)
            }
            AuthError::DatabaseError(error) => write!(f, "{}", error),
            AuthError::CouldNotCreateUserError(error) => write!(f, "{}", error),
            AuthError::CryptographyError(error) => write!(f, "{}", error),
            AuthError::TokenError(error) => write!(f, "{}", error),
            AuthError::PasswordError(error) => write!(f, "{}", error),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

pub type AuthResult<T> = std::result::Result<T, AuthError>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicUser {
    pub uuid: String,
    pub first_name: String,
    pub last_name: String,
    pub username: String,
    pub email: String,
}

#[derive(Serialize, Debug, PartialEq, Eq, Clone, FromRow)]
pub struct User {
    pub uuid: String,
    pub first_name: String,
    pub last_name: String,
    pub username: String,
    pub email: String,
    pub password: String,
    pub can_signin: bool,
    pub email_verified: bool,

    pub updated_on: String,
}

impl AuthUser for User {
    // here we indicate that the id is a string
    type Id = String;

    // map the uuid to the user id in the auth
    fn id(&self) -> Self::Id {
        self.uuid.clone()
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.password.as_bytes()
    }
}

impl User {
    pub fn check_pwd(&self, pwd: &str) -> Result<(), AuthError> {
        check_pwd(pwd, &self.password)
    }

    pub fn to_public(&self) -> PublicUser {
        return PublicUser {
            uuid: self.uuid.clone(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            username: self.username.clone(),
            email: self.email.clone(),
        };
    }
}

///
/// Verify a password matches its hash
///
pub fn check_pwd(pwd: impl AsRef<[u8]>, hash: &str) -> Result<(), AuthError> {
    Ok(verify_password(pwd, hash)?)
}

///
/// Create a password hash
///
pub fn hash_pwd(pwd: &str) -> String {
    return generate_hash(pwd);
}

pub fn create_otp(user: &User) -> String {
    return hash_pwd(&user.updated_on);
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    #[serde(rename(deserialize = "callbackUrl"))]
    pub callback_url: Option<String>,
    pub url: Option<String>,
}

impl Credentials {
    pub fn hash_password(&self) -> String {
        generate_hash(&self.password)
    }
}

impl fmt::Display for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.username, self.password)
    }
}

#[derive(Clone)]
pub struct UserDb {
    pool: Pool<Sqlite>,
}

impl UserDb {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    pub async fn find_user_by_uuid(&self, uuid: &str) -> AuthResult<User> {
        eprintln!("find_user_by_uuid");

        match sqlx::query_as::<_, User>(FIND_USER_BY_UUID_SQL)
            .bind(uuid)
            .fetch_one(&self.pool)
            .await
        {
            Ok(user) => Ok(user),
            Err(_) => Err(AuthError::UserDoesNotExistError(uuid.to_string())),
        }
    }

    pub async fn find_user_by_username(&self, username: &str) -> AuthResult<User> {
        eprintln!("find_user_by_username {}", FIND_USER_BY_USERNAME_SQL);

        match sqlx::query_as::<_, User>(FIND_USER_BY_USERNAME_SQL)
            .bind(username)
            .fetch_one(&self.pool)
            .await
        {
            Ok(user) => Ok(user),
            Err(err) => {
                eprint!("{}", err);
                self.find_user_by_email(username).await
            }
        }
    }

    pub async fn find_user_by_email(&self, email: &str) -> AuthResult<User> {
        eprintln!("find_user_by_email");

        match sqlx::query_as::<_, User>(FIND_USER_BY_EMAIL_SQL)
            .bind(email)
            .fetch_one(&self.pool)
            .await
        {
            Ok(user) => Ok(user),
            Err(_) => Err(AuthError::UserDoesNotExistError(email.to_string())),
        }
    }

    pub async fn username_exists(&self, username: &str) -> bool {
        match self.find_user_by_username(username).await {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub async fn create_user(&self, user: &Credentials) -> AuthResult<User> {
        eprintln!("Creating user");

        if self.username_exists(&user.username).await {
            return Err(AuthError::UserAlreadyExistsError(user.username.clone()));
        }

        let user_id = uuid();

        let hash = user.hash_password();

        match sqlx::query(&CREATE_USER_SQL)
            .bind(&user_id)
            .bind(&user.username)
            .bind(&user.username)
            .bind(hash)
            .execute(&self.pool)
            .await
        {
            Ok(_) => self.find_user_by_username(&user.username).await,
            Err(_) => Err(AuthError::CouldNotCreateUserError(user.username.clone())),
        }
    }

    pub async fn user_verified(&self, uuid: &str) -> AuthResult<()> {
        match sqlx::query(&EMAIL_VERIFIED_SQL)
            .bind(uuid)
            .execute(&self.pool)
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => Err(AuthError::DatabaseError(err.to_string())),
        }
    }

    // Returns element
}

// Make a cached statement
// fn stmt<'a>(
//     conn: &'a PooledConnection<SqliteConnectionManager>,
//     sql: &'a str,
// ) -> CachedStatement<'a> {
//     conn.prepare_cached(sql).unwrap()
// }

// fn row_to_auth_user(row: &rusqlite::Row<'_>) -> Result<AuthUser, rusqlite::Error> {
//     let id: u32 = row.get(0)?;
//     let user_id: String = row.get(1)?;
//     let email: String = row.get(2)?;
//     let hashed_password: String = row.get(3)?;

//     Ok(AuthUser {
//         id,
//         user_id,
//         first_name,
//         last_name,
//         email,
//         password,
//     })
// }

pub fn uuid() -> String {
    return Uuid::new_v4().hyphenated().to_string();
}
