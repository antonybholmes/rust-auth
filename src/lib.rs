use std::fmt::{self, Display};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use sqlx::{FromRow, Pool, Sqlite};
use uuid::Uuid;

use axum_login::AuthUser;
use serde::{Deserialize, Serialize};

pub mod email;
pub mod jwt;
mod tests;

#[derive(Serialize, Debug, PartialEq, Eq, Clone, FromRow)]
pub struct User {
    pub id: u32,
    pub uuid: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub password: String,
}

impl AuthUser for User {
    type Id = String;

    fn id(&self) -> Self::Id {
        self.uuid.clone()
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.password.as_bytes()
    }
}

impl User {
    pub fn check_password(&self, plain_pwd: &str) -> Result<bool, bcrypt::BcryptError> {
        bcrypt::verify(plain_pwd, &self.password)
    }
}

pub fn check_password(plain_pwd: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    bcrypt::verify(plain_pwd, hash)
}

const FIND_USER_BY_UUID_SQL: &'static str = "SELECT id, uuid, first_name, last_name, email, password FROM users WHERE users.uuid = $1 LIMIT 1";
const FIND_USER_BY_USERNAME_SQL: &'static str = "SELECT id, uuid, first_name, last_name, email, password FROM users WHERE users.username = $1 LIMIT 1";
const FIND_USER_BY_EMAIL_SQL: &'static str =
    "SELECT id, uuid, first_name, last_name, email, password FROM users WHERE users.email = $1 LIMIT 1";

const CREATE_USER_SQL: &'static str =
    "INSERT INTO users (uuid, email, password) VALUES($1, $2, $3)";

#[derive(Debug, Clone)]
pub enum AuthError {
    UserDoesNotExistError(String),
    UserAlreadyExistsError(String),
    CouldNotCreateUserError(String),
    DatabaseError(String),
    CryptographyError(String),
    JWTError(String),
}

impl std::error::Error for AuthError {}

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
            AuthError::JWTError(error) => write!(f, "{}", error),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

pub type AuthResult<T> = std::result::Result<T, AuthError>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl Credentials {
    pub fn hash_password(&self) -> Result<String, bcrypt::BcryptError> {
        bcrypt::hash(&self.password, bcrypt::DEFAULT_COST)
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

    pub async fn find_user_by_uuid(&self, uuid: &str) -> AuthResult<Option<User>> {
        eprintln!("find_user_by_uuid");

        match sqlx::query_as::<_, User>(FIND_USER_BY_UUID_SQL)
            .bind(uuid)
            .fetch_one(&self.pool)
            .await
        {
            Ok(user) => Ok(Some(user)),
            Err(_) => Err(AuthError::UserDoesNotExistError(uuid.to_string())),
        }
    }

    pub async fn find_user_by_username(&self, user: &Credentials) -> AuthResult<User> {
        eprintln!("find_user_by_username {}", FIND_USER_BY_USERNAME_SQL);

        match sqlx::query_as::<_, User>(FIND_USER_BY_USERNAME_SQL)
            .bind(&user.username)
            .fetch_one(&self.pool)
            .await
        {
            Ok(user) => Ok(user),
            Err(err) => {
                eprint!("{}", err);
                self.find_user_by_email(user).await
            }
        }
    }

    pub async fn find_user_by_email(&self, user: &Credentials) -> AuthResult<User> {
        eprintln!("find_user_by_email");

        match sqlx::query_as::<_, User>(FIND_USER_BY_EMAIL_SQL)
            .bind(&user.username)
            .fetch_one(&self.pool)
            .await
        {
            Ok(user) => Ok(user),
            Err(_) => Err(AuthError::UserDoesNotExistError(user.username.clone())),
        }
    }

    pub async fn user_exists(&self, user: &Credentials) -> bool {
        match self.find_user_by_username(user).await {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub async fn create_user(&self, user: &Credentials) -> AuthResult<User> {
        eprintln!("Creating user");

        if self.user_exists(user).await {
            return Err(AuthError::UserAlreadyExistsError(user.username.clone()));
        }

        let user_id = otp();

        let hash = match user.hash_password() {
            Ok(hash) => hash,
            Err(_) => {
                return Err(AuthError::CryptographyError(
                    "error creating hash".to_string(),
                ))
            }
        };

        let result = sqlx::query(&CREATE_USER_SQL)
            .bind(&user_id)
            .bind(&user.username)
            .bind(hash)
            .execute(&self.pool)
            .await;

        match result {
            Ok(_) => self.find_user_by_username(user).await,
            Err(_) => Err(AuthError::CouldNotCreateUserError(user.username.clone())),
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

pub fn otp() -> String {
    return Uuid::new_v4().hyphenated().to_string();
}
