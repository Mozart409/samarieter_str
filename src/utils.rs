use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

use crate::errors::AppError;

pub fn hash_password(password: &str) -> Result<String, AppError> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|e| {
            log::error!("Failed to hash password: {}", e);
            AppError::PasswordError(e.to_string())
        })?
        .to_string())
}

pub fn verify_password(password: &str, stored_hashed: &str) -> Result<bool, AppError> {
    let salt = &SaltString::generate(&mut OsRng);
    // create argon2 hash from password and compare strictly with stored hash
    let pwd_hash = Argon2::default()
        .hash_password(password.as_bytes(), salt)
        .map_err(|e| {
            log::error!("Failed to hash password for verification: {}", e);
            AppError::PasswordError(e.to_string())
        })?;

    if stored_hashed == pwd_hash.to_string() {
        Ok(true)
    } else {
        log::warn!("Password verification failed");
        Ok(false)
    }
}
