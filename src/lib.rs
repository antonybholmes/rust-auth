use std::fmt::Display;

use r2d2_sqlite::SqliteConnectionManager;

use uuid::Uuid;

use serde::{Deserialize, Serialize};

pub mod jwt;
mod tests;

const FIND_USER_BY_EMAIL_SQL: &'static str =
    r#"SELECT id, user_id, password FROM users WHERE users.email = ?"#;
const CREATE_USER_SQL: &'static str =
    r#"INSERT INTO users (user_id, email, password) VALUES(?, ?, ?)"#;

#[derive(Debug, Clone)]
pub enum AuthError {
    UserAlreadyExistsError(LoginUser),
    DatabaseError(String),
    CryptographyError(String),
    JWTError(String),

}

impl std::error::Error for AuthError {}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::UserAlreadyExistsError(user) => write!(f, "{} already exists", user.email),
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
    pool: r2d2::Pool<SqliteConnectionManager>,
}

impl UserDb {
    pub fn new(file: &str) -> AuthResult<Self> {
        let manager: SqliteConnectionManager = SqliteConnectionManager::file(file);

        let pool: r2d2::Pool<SqliteConnectionManager> = match r2d2::Pool::builder().build(manager) {
            Ok(pool) => pool,
            Err(_) => return Err(AuthError::DatabaseError("error getting connection".to_string())),
        };

        Ok(UserDb { pool })
    }

    pub fn find_user_by_email(&self, user: &LoginUser) -> AuthResult<Vec<AuthUser>> {
        let conn: r2d2::PooledConnection<SqliteConnectionManager> = match self.pool.get() {
            Ok(conn) => conn,
            Err(_) => return Err(AuthError::DatabaseError("error getting connection".to_string())),
        };

        let mut stmt: rusqlite::CachedStatement<'_> =
            match conn.prepare_cached(FIND_USER_BY_EMAIL_SQL) {
                Ok(stmt) => stmt,
                Err(_) => return Err(AuthError::DatabaseError("error creating statement".to_string())),
            };

        let mapped_rows = match stmt
            .query_map(rusqlite::params![user.email], |row: &rusqlite::Row<'_>| {
                row_to_auth_user(row)
            }) {
            Ok(mapped_rows) => mapped_rows,
            Err(_) => return Err(AuthError::DatabaseError("error running query".to_string())),
        };

        let auth_users: Vec<AuthUser> = mapped_rows
            .filter_map(|x: Result<AuthUser, rusqlite::Error>| x.ok())
            .collect::<Vec<AuthUser>>();

        Ok(auth_users)
    }

    pub fn create_user(&self, user: &LoginUser) -> AuthResult<AuthUser> {
        let mut auth_users: Vec<AuthUser> = self.find_user_by_email(user)?;

        if auth_users.len() > 0 {
            return Err(AuthError::UserAlreadyExistsError(user.clone()));
        }

        let uuid = Uuid::new_v4().hyphenated().to_string().to_uppercase();

        let hash = match user.hash_password() {
            Ok(hash) => hash,
            Err(_) => return Err(AuthError::CryptographyError("error creating hash".to_string())),
        };

        let conn: r2d2::PooledConnection<SqliteConnectionManager> = match self.pool.get() {
            Ok(stmt) => stmt,
            Err(_) => return Err(AuthError::DatabaseError("error getting pool".to_string())),
        };

        let mut stmt: rusqlite::CachedStatement<'_> = match conn.prepare_cached(CREATE_USER_SQL) {
            Ok(stmt) => stmt,
            Err(_) => return Err(AuthError::DatabaseError("error creating statement".to_string())),
        };

        match stmt.execute(rusqlite::params![uuid, user.email, hash]) {
            Ok(_) => (),
            Err(_) => return Err(AuthError::DatabaseError("error executing insert".to_string())),
        }

        auth_users = self.find_user_by_email(user)?;

        let auth_user: AuthUser = auth_users.get(0).unwrap().clone();

        Ok(auth_user)
    }

    // Returns element
}

// fn mapped_rows_to_features(mapped_rows: MappedRows<'_, impl Fn(&Row<'_>) -> Result<GenomicFeature, Error>>) -> Vec<GenomicFeature> {
//     return mapped_rows
//     .filter_map(|x: Result<GenomicFeature, rusqlite::Error>| x.ok())
//     .collect::<Vec<GenomicFeature>>();
// }

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
