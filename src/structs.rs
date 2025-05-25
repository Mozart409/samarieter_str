use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Deserialize, Serialize, Debug, Clone, FromRow)]
pub struct User {
    pub id: i64,
    pub tenant_id: i64,
    pub created_at: String,
    pub updated_at: String,
    pub email: String,
    pub pwd_hash: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, FromRow)]
pub struct Tenant {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, FromRow)]
pub struct Item {
    pub id: i64,
    pub name: String,
    pub amount: String,
    pub tenant_id: i64,
    pub created_at: String,
    pub updated_at: String,
}
