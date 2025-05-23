#[macro_use]
extern crate lazy_static;
use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use db::{create_tenant, create_user};

use std::{env, str::FromStr};
use tera::Tera;
use utils::verify_password;
mod utils;

use actix_files::{Files, NamedFile};
use actix_web::{
    cookie::Key,
    get,
    http::{Method, StatusCode},
    middleware, post,
    web::{self, Data},
    App, Either, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder,
};
use log::info;
use serde::{Deserialize, Serialize};
use sqlx::{
    prelude::FromRow,
    sqlite::{SqliteConnectOptions, SqliteJournalMode},
    SqlitePool,
};
mod db;
mod errors;
use errors::AppError;
use tera::Context;

#[derive(Debug, Clone)]
struct AppState {
    db_pool: SqlitePool,
}

lazy_static! {
    pub static ref TEMPLATES: Tera = {
        let mut tera = match Tera::new("templates/**/*") {
            Ok(t) => t,
            Err(e) => {
                log::error!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };
        tera.autoescape_on(vec![".html", ".sql"]);
      //  tera.register_filter("do_nothing", do_nothing_filter);
        tera
    };
}

fn get_session_key() -> Key {
    let key_str = env::var("SESSION_KEY").unwrap_or_else(|_| {
        log::error!("FATAL: SESSION_KEY environment variable not set");
        std::process::exit(1);
    });
    Key::from(key_str.as_bytes())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // let database_url = env::var("DATABASE_URL").map_err(|e| {
    //     log::error!("FATAL: DATABASE_URL environment variable not set: {}", e);
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
            .wrap(IdentityMiddleware::default())
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                get_session_key(),
            ))
            // enable logger - always register Actix Web Logger middleware last
            .wrap(middleware::Logger::default())
            .service(Files::new("/static", "static").show_files_listing())
            .service(favicon_handler)
            .service(index_handler)
            .service(register_handler)
            .service(register_form_handler)
            .service(login_handler)
            .service(login_form_handler)
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
async fn index_handler(
    state: web::Data<AppState>,
    identity: Option<Identity>,
) -> Result<impl Responder, AppError> {
    let users = db::get_all_users(&state).await.map_err(|e| {
        log::error!("Failed to get users: {}", e);
        AppError::DatabaseError(e)
    })?;

    let tenants = db::get_all_tenants(&state).await.map_err(|e| {
        log::error!("Failed to get tenants: {}", e);
        AppError::DatabaseError(e)
    })?;

    let id = match identity.map(|id| id.id()) {
        None => "anonymous".to_owned(),
        Some(Ok(id)) => id,
        Some(Err(err)) => return Err(AppError::IdentityError(err)),
    };

    let mut context = Context::new();
    context.insert("title", "Welcome to the index page");
    context.insert("description", "This is the index page");
    context.insert("users", &users);
    context.insert("tenants", &tenants);
    context.insert("version", env!("CARGO_PKG_VERSION"));
    context.insert("identity", &id);

    let rendered = TEMPLATES.render("home.html", &context).map_err(|e| {
        log::error!("Failed to render template: {}", e);
        AppError::TemplateError(e)
    })?;

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(rendered))
}

#[derive(Deserialize)]
struct Login {
    email: String,
    password: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, FromRow)]
struct User {
    id: i64,
    tenant_id: i64,
    created_at: String,
    updated_at: String,
    email: String,
    pwd_hash: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, FromRow)]
struct Tenants {
    id: i64,
    name: String,
    created_at: String,
    updated_at: String,
}

#[post("/login")]
async fn login_form_handler(
    web::Form(form): web::Form<Login>,
    state: Data<AppState>,
    request: HttpRequest,
) -> Result<impl Responder, AppError> {
    // validate the form data, valid email and password
    if form.email.is_empty() || form.password.is_empty() {
        return Ok(HttpResponse::BadRequest().body("All fields are required"));
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
    // lowercase form.email
    let lc_email = form.email.to_lowercase();

    // check if email is already registered
    let mut conn = state.db_pool.acquire().await.map_err(|e| {
        log::error!("Failed to acquire database connection: {}", e);
        AppError::DatabaseConnectionError(e)
    })?;

    let row = sqlx::query_as!(
        User,
        r#"
        SELECT id, tenant_id, created_at, updated_at, email, pwd_hash
        FROM users
        WHERE email = ?
        "#,
        lc_email
    )
    .fetch_optional(&mut *conn)
    .await;

    match row {
        Ok(Some(user_record)) => {
            // Compare stored hash with provided password (example shown below)
            if verify_password(&form.password, &user_record.pwd_hash) {
                // Create (remember) an identity session for the authenticated user
                Identity::login(&request.extensions(), user_record.id.to_string()).unwrap();

                return Ok(HttpResponse::Ok().body("Login successful"));
            } else {
                return Ok(HttpResponse::Unauthorized().body("Invalid credentials"));
            }
        }
        Ok(None) => Ok(HttpResponse::Unauthorized().body("User does not exist")),
        Err(e) => {
            eprintln!("Database error: {:?}", e);
            Ok(HttpResponse::InternalServerError().body("Database error"))
        }
    }
}

#[derive(Deserialize)]
struct Register {
    email: String,
    password: String,
    password2: String,
    tenant: String,
}
/// Register Form handler
#[post("/register")]
async fn register_form_handler(
    web::Form(form): web::Form<Register>,
    state: Data<AppState>,
    request: HttpRequest,
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

    // create tenant

    let tenant = create_tenant(&state, lc_tenant).await?;

    let user = create_user(&state, tenant.id, lc_email, form.password).await?;

    Identity::login(&request.extensions(), user.email.into()).unwrap();

    Ok(HttpResponse::SeeOther()
        .append_header(("Location", "/"))
        .body("User registered successfully"))
}

#[post("/logout")]
async fn logout(user: Identity) -> impl Responder {
    user.logout();
    HttpResponse::Ok()
}

/// Register handler
#[get("/register")]
async fn register_handler() -> Result<impl Responder, AppError> {
    let mut context = Context::new();
    context.insert("title", "Register");
    context.insert("description", "This is the register page");

    let rendered = TEMPLATES.render("register.html", &context).map_err(|e| {
        log::error!("Failed to render template: {}", e);
        AppError::TemplateError(e)
    })?;

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(rendered))
}

/// Register handler
#[get("/login")]
async fn login_handler() -> Result<impl Responder, AppError> {
    let mut context = Context::new();
    context.insert("title", "Welcome to the login page");
    context.insert("description", "This is the login page");

    let rendered = TEMPLATES.render("login.html", &context).map_err(|e| {
        log::error!("Failed to render template: {}", e);
        AppError::TemplateError(e)
    })?;

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(rendered))
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
