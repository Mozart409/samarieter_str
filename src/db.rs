use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

use crate::{
    errors::AppError,
    structs::{Item, Tenant, User},
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

pub async fn get_all_tenants(state: &AppState) -> Result<Vec<Tenant>, sqlx::Error> {
    let pool = state.db_pool.clone();
    let tenants = sqlx::query_as::<_, Tenant>("SELECT * FROM tenants")
        .fetch_all(&pool)
        .await?;
    Ok(tenants)
}

pub async fn get_user_by_email(state: &AppState, email: String) -> Result<User, sqlx::Error> {
    let pool = state.db_pool.clone();
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(&pool)
        .await?;
    match user {
        Some(u) => Ok(u),
        None => Err(sqlx::Error::RowNotFound),
    }
}

pub async fn _get_user_by_id(state: &AppState, id: i64) -> Result<User, sqlx::Error> {
    let pool = state.db_pool.clone();
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await?;
    Ok(user)
}
pub async fn _get_tenant_by_id(state: &AppState, id: i64) -> Result<Tenant, sqlx::Error> {
    let pool = state.db_pool.clone();
    let tenant = sqlx::query_as::<_, Tenant>("SELECT * FROM tenants WHERE id = $1")
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
        .map_err(AppError::DatabaseError)?;
    log::info!("User created: {:?}", user);
    Ok(user)
}

pub async fn create_tenant(state: &AppState, tenant_name: String) -> Result<Tenant, sqlx::Error> {
    let created_at = chrono::Utc::now().to_string();
    let pool = state.db_pool.clone();
    let tenant = sqlx::query_as::<_, Tenant>(
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

pub async fn _delete_user(state: &AppState, id: i64) -> Result<(), sqlx::Error> {
    let pool = state.db_pool.clone();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await?;
    log::info!("User with id {} deleted", id);
    Ok(())
}
pub async fn _delete_tenant(state: &AppState, id: i64) -> Result<(), sqlx::Error> {
    let pool = state.db_pool.clone();
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await?;
    log::info!("Tenant with id {} deleted", id);
    Ok(())
}
pub async fn update_user(
    state: &AppState,
    id: i64,
    email: Option<String>,
    password: Option<String>,
) -> Result<User, AppError> {
    let pool = state.db_pool.clone();
    // We'll build the query and bind parameters in order
    let mut param_index = 2;
    let mut query = String::from("UPDATE users SET updated_at = $1");
    let updated_at = chrono::Utc::now().to_string();

    let mut email_val = None;
    let mut pwd_hash_val = None;

    if email.is_some() {
        query.push_str(&format!(", email = ${}", param_index));
        email_val = email;
        param_index += 1;
    }
    if let Some(password) = password {
        let pwd_hash = Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .map_err(|e| {
                log::error!("Failed to hash password: {}", e);
                AppError::PasswordError(e.to_string())
            })?
            .to_string();
        query.push_str(&format!(", pwd_hash = ${}", param_index));
        pwd_hash_val = Some(pwd_hash);
        param_index += 1;
    }

    query.push_str(&format!(" WHERE id = ${} RETURNING *", param_index));

    let mut q = sqlx::query_as::<_, User>(&query);
    q = q.bind(&updated_at);
    if let Some(email) = &email_val {
        q = q.bind(email);
    }
    if let Some(pwd_hash) = &pwd_hash_val {
        q = q.bind(pwd_hash);
    }
    q = q.bind(id);

    let user = q.fetch_one(&pool).await.map_err(AppError::DatabaseError)?;

    log::info!("User updated: {:?}", user);
    Ok(user)
}

pub async fn create_item(
    state: &AppState,
    tenant_id: i64,
    name: String,
    amount: String,
) -> Result<(), sqlx::Error> {
    let created_at = chrono::Utc::now().to_string();
    let pool = state.db_pool.clone();
    log::info!("Item created for tenant_id {}: {}", tenant_id, name);
    sqlx::query("INSERT INTO items (tenant_id, created_at, updated_at, name, amount) VALUES ($1, $2, $3, $4, $5)")
        .bind(tenant_id)
        .bind(&created_at)
        .bind(&created_at)
        .bind(name)
        .bind(amount)
        .execute(&pool)
        .await?;
    Ok(())
}

pub async fn get_all_items(state: &AppState, tenant_id: i64) -> Result<Vec<Item>, sqlx::Error> {
    let pool = state.db_pool.clone();
    let items = sqlx::query_as!(Item, "SELECT * FROM items WHERE tenant_id = $1", tenant_id)
        .fetch_all(&pool)
        .await?;
    log::info!("Items for tenant_id {}: {:?}", tenant_id, items);
    Ok(items)
}

pub async fn delete_item(
    state: &AppState,
    tenant_id: i64,
    item_id: i64,
) -> Result<(), sqlx::Error> {
    let pool = state.db_pool.clone();
    sqlx::query("DELETE FROM items WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(item_id)
        .execute(&pool)
        .await?;
    log::info!(
        "Item with id {} deleted for tenant_id {}",
        item_id,
        tenant_id
    );
    Ok(())
}
