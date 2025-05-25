use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

use crate::{
    errors::AppError,
    routes::{Tenants, User},
    AppState,
};

pub async fn get_all_users(state: &AppState) -> Result<Vec<User>, sqlx::Error> {
    let pool = state.db_pool.clone();
    let users = sqlx::query_as::<_, User>("SELECT * FROM users")
        .fetch_all(&pool)
        .await?;
    log::info!("Users: {:?}", users);
    Ok(users)
}

pub async fn get_all_tenants(state: &AppState) -> Result<Vec<Tenants>, sqlx::Error> {
    let pool = state.db_pool.clone();
    let tenants = sqlx::query_as::<_, Tenants>("SELECT * FROM tenants")
        .fetch_all(&pool)
        .await?;
    Ok(tenants)
}

pub async fn get_user_by_id(state: &AppState, id: i32) -> Result<User, sqlx::Error> {
    let pool = state.db_pool.clone();
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await?;
    Ok(user)
}
pub async fn get_tenant_by_id(state: &AppState, id: i32) -> Result<Tenants, sqlx::Error> {
    let pool = state.db_pool.clone();
    let tenant = sqlx::query_as::<_, Tenants>("SELECT * FROM tenants WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await?;
    Ok(tenant)
}
pub async fn create_user(
    state: &AppState,
    tenant_id: i64,
    email: String,
    password: String,
) -> Result<User, AppError> {
    let created_at = chrono::Utc::now().to_string();
    let pwd_hash = Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|e| {
            log::error!("Failed to hash password: {}", e);
            AppError::PasswordError(e.to_string())
        })?
        .to_string();
    let pool = state.db_pool.clone();
    let user = sqlx::query_as::<_, User>("INSERT INTO users ( tenant_id, created_at, updated_at, email, pwd_hash) VALUES ($1, $2, $3, $4, $5) RETURNING *")
        .bind(tenant_id)
        .bind(&created_at)
        .bind(&created_at)
        .bind(email)
        .bind(pwd_hash)
        .fetch_one(&pool)
        .await
        .map_err(|e| AppError::DatabaseError(e))?;
    log::info!("User created: {:?}", user);
    Ok(user)
}

pub async fn create_tenant(state: &AppState, tenant_name: String) -> Result<Tenants, sqlx::Error> {
    let created_at = chrono::Utc::now().to_string();
    let pool = state.db_pool.clone();
    let tenant = sqlx::query_as::<_, Tenants>(
        "INSERT INTO tenants ( created_at, updated_at, name) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(&created_at)
    .bind(&created_at)
    .bind(tenant_name)
    .fetch_one(&pool)
    .await?;
    log::info!("Tenant created: {:?}", tenant);
    Ok(tenant)
}
