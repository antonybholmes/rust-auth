use std::fmt::Display;

use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;

use rusqlite::CachedStatement;
use uuid::Uuid;

use serde::{Deserialize, Serialize};

pub mod jwt;
pub mod email;
mod tests;



const FIND_USER_BY_EMAIL_SQL: &'static str =
    r#"SELECT id, user_id, email, password FROM users WHERE users.email = ?1"#;

const CREATE_USER_SQL: &'static str =
    r#"INSERT INTO users (user_id, email, password) VALUES(?1, ?2, ?3)"#;

#[derive(Debug, Clone)]
pub enum AuthError {
    UserDoesNotExist(String),
    UserAlreadyExistsError(String),
    DatabaseError(String),
    CryptographyError(String),
    JWTError(String),
}

//impl std::error::Error for AuthError {}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::UserDoesNotExist(user) => write!(f, "account for {} does not exist", user),
            AuthError::UserAlreadyExistsError(user) => {
                write!(f, "acount for {} already exists", user)
            }
            AuthError::DatabaseError(error) => write!(f, "{}", error),
            AuthError::CryptographyError(error) => write!(f, "{}", error),
            AuthError::JWTError(error) => write!(f, "{}", error),
        }
    }
}

pub type AuthResult<T> = std::result::Result<T, AuthError>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct LoginUser {
    email: String,
    password: String,
}

impl LoginUser {
    pub fn hash_password(&self) -> Result<String, bcrypt::BcryptError> {
        bcrypt::hash(&self.password, bcrypt::DEFAULT_COST)
    }
}

#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub struct AuthUser {
    id: u32,
    user_id: String,
    email: String,
    hashed_password: String,
}

impl AuthUser {
    pub fn check_password(&self, plain_pwd: &str) -> Result<bool, bcrypt::BcryptError> {
        bcrypt::verify(plain_pwd, &self.hashed_password)
    }
}

pub struct UserDb {
    pool: Pool<SqliteConnectionManager>,
}

impl UserDb {
    pub fn new(file: &str) -> Self {
        let manager: SqliteConnectionManager = SqliteConnectionManager::file(file);

        let pool = Pool::builder().build(manager).unwrap();

        Self { pool }
    }

    fn conn(&self) -> PooledConnection<SqliteConnectionManager> {
        self.pool.get().unwrap()
    }

    pub fn find_user_by_email(&self, user: &LoginUser) -> AuthResult<AuthUser> {
        eprintln!("find_user_by_email");

        let conn = self.conn();

        let mut stmt = conn.prepare_cached(FIND_USER_BY_EMAIL_SQL).unwrap();

        let mapped_rows =
            stmt.query_map(rusqlite::params![user.email], |row| row_to_auth_user(row)).unwrap();

        let auth_users: Vec<AuthUser> = mapped_rows
            .filter_map(|x| x.ok())
            .collect::<Vec<AuthUser>>();

        if auth_users.len() == 0 {
            return Err(AuthError::UserDoesNotExist(user.email.clone()));
        }

        Ok(auth_users.get(0).unwrap().clone())
    }

    pub fn user_exists(&self, user: &LoginUser) -> bool {
        match self.find_user_by_email(user) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub fn create_user(&self, user: &LoginUser) -> AuthResult<AuthUser> {
        eprintln!("Creating");

        if self.user_exists(user) {
            return Err(AuthError::UserAlreadyExistsError(user.email.clone()));
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

        let conn = self.conn();

        let mut stmt = stmt(&conn, CREATE_USER_SQL);

        stmt.execute(rusqlite::params![user_id, user.email, hash]).unwrap();

        let auth_user: AuthUser = self.find_user_by_email(user)?;

        Ok(auth_user)
    }

    // Returns element
}

// Make a cached statement
fn stmt<'a> (
    conn: &'a PooledConnection<SqliteConnectionManager>,
    sql: &'a str,
) -> CachedStatement<'a>  {
    conn.prepare_cached(sql).unwrap()
}

fn row_to_auth_user(row: &rusqlite::Row<'_>) -> Result<AuthUser, rusqlite::Error> {
    let id: u32 = row.get(0)?;
    let user_id: String = row.get(1)?;
    let email: String = row.get(2)?;
    let hashed_password: String = row.get(3)?;

    Ok(AuthUser {
        id,
        user_id,
        email,
        hashed_password,
    })
}

pub fn otp() -> String {
    return Uuid::new_v4().hyphenated().to_string();
}

