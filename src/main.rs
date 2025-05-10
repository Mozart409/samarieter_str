use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sqids::Sqids;
use std::{env, str::FromStr};

use actix_files::{Files, NamedFile};
use actix_web::{
    get,
    http::{Method, StatusCode},
    middleware, post,
    web::{self, Data},
    App, Either, HttpResponse, HttpServer, Responder,
};
use log::info;
use serde::Deserialize;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode},
    SqlitePool,
};
mod errors;
use errors::AppError;

struct AppState {
    db_pool: SqlitePool,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // let database_url = env::var("DATABASE_URL").map_err(|e| {
    //     error!("FATAL: DATABASE_URL environment variable not set: {}", e);
    //     AppError::MissingDatabaseUrl
    // })?;
    //

    let database_url = format!("sqlite://samarieter_str.db");

    let opts = SqliteConnectOptions::from_str(&database_url)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .read_only(false)
        .busy_timeout(std::time::Duration::from_secs(5));

    let db_pool = SqlitePool::connect_with(opts)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    sqlx::migrate!().run(&db_pool).await.expect("Migrate Error");

    info!("Database migrated successfully");

    info!("Starting HTTP server on http://localhost:8080/");

    HttpServer::new(move || {
        App::new()
            // enable automatic response compression - usually register this first
            .wrap(middleware::Compress::default())
            // enable logger - always register Actix Web Logger middleware last
            .wrap(middleware::Logger::default())
            .service(Files::new("/static", "static").show_files_listing())
            .service(favicon_handler)
            .service(index_handler)
            .service(register_handler)
            .service(register_form_handler)
            .service(login_handler)
            .app_data(Data::new(AppState {
                db_pool: db_pool.clone(),
            }))
            //
            .default_service(web::to(default_handler))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
/// index handler
#[get("/")]
async fn index_handler() -> Result<impl Responder, AppError> {
    Ok(NamedFile::open("static/index.html")?)
}

#[derive(Deserialize)]
struct Login {
    email: String,
    password: String,
}

/// Login handler
#[get("/login")]
async fn login_handler(web::Form(form): web::Form<Login>) -> Result<impl Responder, AppError> {
    Ok(NamedFile::open("static/login.html")?)
}
#[derive(Deserialize)]
struct Register {
    email: String,
    password: String,
    password2: String,
    tenant: String,
}
/// Register Form handler
#[post("/register_form")]
async fn register_form_handler(
    web::Form(form): web::Form<Register>,
    state: Data<AppState>,
) -> Result<impl Responder, AppError> {
    // validate the form data, valid email and repeated password and password2
    if form.email.is_empty()
        || form.password.is_empty()
        || form.password2.is_empty()
        || form.tenant.is_empty()
    {
        return Ok(HttpResponse::BadRequest().body("All fields are required"));
    }
    if form.password != form.password2 {
        return Ok(HttpResponse::BadRequest().body("Passwords do not match"));
    }
    if !form.email.contains('@') {
        return Ok(HttpResponse::BadRequest().body("Invalid email address"));
    }
    if form.password.len() < 12 {
        return Ok(HttpResponse::BadRequest().body("Password must be at least 12 characters long"));
    }
    if form.password.len() > 128 {
        return Ok(HttpResponse::BadRequest().body("Password must be at most 128 characters long"));
    }
    // check if password is strong numbers, letters, special characters
    if !form.password.chars().any(|c| c.is_digit(10))
        || !form.password.chars().any(|c| c.is_alphabetic())
        || !form
            .password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;':\",.<>?/".contains(c))
    {
        return Ok(HttpResponse::BadRequest().body(
            "Password must contain at least one number, one letter and one special character",
        ));
    }
    // lowercase form.tenant and form.email
    let lc_email = form.email.to_lowercase();
    let lc_tenant = form.tenant.to_lowercase();

    // check if email is already registered
    let mut conn = state
        .db_pool
        .acquire()
        .await
        .expect("Failed to acquire database connection");

    let tenant_exists = sqlx::query!("SELECT name FROM tenants WHERE name = ? LIMIT 1", lc_tenant)
        .fetch_optional(&mut *conn)
        .await
        .expect("Failed to check tenant")
        .is_none();
    if !tenant_exists {
        return Ok(HttpResponse::BadRequest().body("Tenant already registered"));
    }

    // Get count of tenants and encode it to a sqids
    let tenant_count: u64 = sqlx::query!("SELECT COUNT(*) as count FROM tenants")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| {
            log::error!("Failed to get tenant count: {}", e);
            AppError::DatabaseError(sqlx::Error::InvalidArgument(e.to_string()))
        })?
        .count
        .try_into()
        .unwrap();

    // encode the tenant count to a sqids
    let sqids = Sqids::default();

    let tenant_public_id = sqids
        .encode(&[tenant_count])
        .map_err(|e| AppError::DatabaseError(sqlx::Error::InvalidArgument(e.to_string())))?;

    // create tenant
    let tenant = sqlx::query!(
        "INSERT INTO tenants (name, created_at, updated_at, public_id) VALUES (?, datetime('now'), datetime('now'), ?)",
        lc_tenant,
        tenant_public_id
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        log::error!("Failed to insert tenant: {}", e);
        AppError::DatabaseError(sqlx::Error::InvalidArgument(e.to_string()))
    })?;

    let unused_email = sqlx::query!("SELECT email FROM users WHERE email = ? LIMIT 1", lc_email)
        .fetch_optional(&mut *conn)
        .await
        .expect("Failed to check email")
        .is_none();
    if !unused_email {
        return Ok(HttpResponse::BadRequest().body("Email already registered"));
    }

    // hash the password with argon2
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    let hashed_password = argon2
        .hash_password(form.password.as_bytes(), &salt)
        .map_err(|e| {
            log::error!("Password hashing failed: {}", e);
            AppError::DatabaseError(sqlx::Error::InvalidArgument(e.to_string()))
        })?
        .to_string();
    // check if the password is hashed correctly
    let parsed_hash = PasswordHash::new(&hashed_password).map_err(|e| {
        log::error!("Password hash parsing failed: {}", e);
        AppError::DatabaseError(sqlx::Error::InvalidArgument(e.to_string()))
    })?;
    assert!(Argon2::default()
        .verify_password(form.password.as_bytes(), &parsed_hash)
        .is_ok());

    // encode the user count to a sqids

    let user_count: u64 = sqlx::query!("SELECT COUNT(*) as count FROM users")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| {
            log::error!("Failed to get user count: {}", e);
            AppError::DatabaseError(sqlx::Error::InvalidArgument(e.to_string()))
        })?
        .count
        .try_into()
        .unwrap();
    let public_user_id = sqids
        .encode(&[user_count])
        .map_err(|e| AppError::DatabaseError(sqlx::Error::InvalidArgument(e.to_string())))?;

    // insert the user into the database with created_at and updated_at timestamps
    let registered_user = sqlx::query!(
        "INSERT INTO users (email, pwd_hash, created_at, updated_at, tenant_id, public_id)
        SELECT ?, ?, datetime('now'), datetime('now'),?, id FROM tenants WHERE name = ?",
        lc_email,
        hashed_password,
        lc_tenant,
        public_user_id
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        log::error!("Failed to insert user: {}", e);
        AppError::DatabaseError
    });

    if registered_user.is_err() {
        return Ok(HttpResponse::InternalServerError().body("Failed to register user"));
    }

    // redirect to the home page
    Ok(HttpResponse::SeeOther()
        .append_header(("Location", "/"))
        .body("User registered successfully"))
}

/// Register handler
#[get("/register")]
async fn register_handler() -> Result<impl Responder, AppError> {
    Ok(NamedFile::open("static/register.html")?)
}
/// favicon handler
#[get("/favicon")]
async fn favicon_handler() -> Result<impl Responder, AppError> {
    Ok(NamedFile::open("static/favicon.ico")?)
}

async fn default_handler(req_method: Method) -> Result<impl Responder, std::io::Error> {
    match req_method {
        Method::GET => {
            let file = NamedFile::open("static/404.html")?
                .customize()
                .with_status(StatusCode::NOT_FOUND);
            Ok(Either::Left(file))
        }
        _ => Ok(Either::Right(HttpResponse::MethodNotAllowed().finish())),
    }
}
