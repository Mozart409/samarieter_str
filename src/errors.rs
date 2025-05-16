use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use sqlx::{migrate::MigrateError, Error as SqlxError};
use std::{env::VarError, io};
use thiserror::Error;
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(SqlxError),

    #[error("Not found")]
    NotFound,

    #[error("Internal server error")]
    InternalServerError,

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Environment variable error: {0}")]
    EnvVarError(#[from] VarError),

    #[error("SQLx error: {0}")]
    SqlxError(SqlxError),

    #[error("Missing DATABASE_URL environment variable")]
    MissingDatabaseUrl,

    #[error("Database connection error: {0}")]
    DatabaseConnectionError(sqlx::Error),

    #[error("Migration error: {0}")]
    MigrateError(MigrateError),

    #[error("Unknown error")]
    UnknownError,

    #[error("Password error: {0}")]
    PasswordError(String),
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::EnvVarError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::SqlxError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::MissingDatabaseUrl => StatusCode::BAD_REQUEST,
            AppError::DatabaseConnectionError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::IoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::MigrateError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::UnknownError => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::PasswordError(_) => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(self.to_string())
    }
}

impl From<AppError> for io::Error {
    fn from(err: AppError) -> Self {
        io::Error::new(io::ErrorKind::Other, err.to_string())
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::DatabaseError(err)
    }
}
