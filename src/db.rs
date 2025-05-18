use crate::{AppState, Tenants, User};

pub async fn get_all_users(state: &AppState) -> Result<Vec<User>, sqlx::Error> {
    let pool = state.db_pool.clone();
    let users = sqlx::query_as::<_, User>("SELECT * FROM users")
        .fetch_all(&pool)
        .await?;
    Ok(users)
}

pub async fn get_all_tenants(state: &AppState) -> Result<Vec<Tenants>, sqlx::Error> {
    let pool = state.db_pool.clone();
    let tenants = sqlx::query_as::<_, Tenants>("SELECT * FROM tenants")
        .fetch_all(&pool)
        .await?;
    Ok(tenants)
}
