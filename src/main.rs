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
}
/// Register Form handler
#[post("/register_form")]
async fn register_form_handler(
    web::Form(form): web::Form<Register>,
    state: AppState,
) -> HttpResponse {
    // validate the form data, valid email and repeated password and password2
    if form.email.is_empty() || form.password.is_empty() || form.password2.is_empty() {
        return HttpResponse::BadRequest().body("All fields are required");
    }
    if form.password != form.password2 {
        return HttpResponse::BadRequest().body("Passwords do not match");
    }
    if !form.email.contains('@') {
        return HttpResponse::BadRequest().body("Invalid email address");
    }
    if form.password.len() < 12 {
        return HttpResponse::BadRequest().body("Password must be at least 12 characters long");
    }
    if form.password.len() > 128 {
        return HttpResponse::BadRequest().body("Password must be at most 128 characters long");
    }
    // check if password is strong numbers, letters, special characters
    if !form.password.chars().any(|c| c.is_digit(10))
        || !form.password.chars().any(|c| c.is_alphabetic())
        || !form
            .password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;':\",.<>?/".contains(c))
    {
        return HttpResponse::BadRequest().body(
            "Password must contain at least one number, one letter and one special character",
        );
    }
    // check if email is already registered
    let mut conn = state
        .db_pool
        .acquire()
        .await
        .expect("Failed to acquire database connection");

    let unused_email = sqlx::query!(
        "SELECT email FROM users WHERE email = ? LIMIT 1",
        form.email
    )
    .fetch_one(&mut conn)
    .await
    .expect("Failed to check email")
    .is_none();
    if !unused_email {
        return HttpResponse::BadRequest().body("Email already registered");
    }
    // insert the user into the database
    sqlx::query!(
        "INSERT INTO users (email, pwd_hash) VALUES (?, ?)",
        form.email,
        form.password
    )
    .execute(&mut conn)
    .await
    .expect("Failed to insert user");

    HttpResponse::Ok().body(format!(
        "Email {}, Password {}, Password2 {}",
        form.email, form.password, form.password2
    ))
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
