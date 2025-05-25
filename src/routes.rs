use actix_identity::Identity;
use db::{create_tenant, create_user};

use std::env;
use utils::verify_password;

use actix_files::NamedFile;
use actix_web::{
    get, post,
    web::{self, Data}, HttpMessage, HttpRequest, HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

use errors::AppError;
use tera::Context;

use crate::{db, errors, utils, AppState, TEMPLATES};

#[get("/")]
pub async fn index_handler(
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
pub struct Login {
    email: String,
    password: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, FromRow)]
pub struct User {
    id: i64,
    tenant_id: i64,
    created_at: String,
    updated_at: String,
    email: String,
    pwd_hash: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, FromRow)]
pub struct Tenants {
    id: i64,
    name: String,
    created_at: String,
    updated_at: String,
}

#[post("/login")]
pub async fn login_form_handler(
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
pub struct Register {
    email: String,
    password: String,
    password2: String,
    tenant: String,
}
/// Register Form handler
#[post("/register")]
pub async fn register_form_handler(
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
pub async fn logout(user: Identity) -> impl Responder {
    user.logout();
    HttpResponse::Ok()
}

/// Register handler
#[get("/register")]
pub async fn register_handler() -> Result<impl Responder, AppError> {
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
pub async fn login_handler() -> Result<impl Responder, AppError> {
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
pub async fn favicon_handler() -> Result<impl Responder, AppError> {
    Ok(NamedFile::open("static/favicon.ico")?)
}

#[get("/dashboard")]
pub async fn dashboard_handler(identity: Option<Identity>) -> Result<impl Responder, AppError> {
    // Check if the user is logged in
    if identity.is_none() {
        return Ok(HttpResponse::Unauthorized().body("Unauthorized"));
    }

    let mut context = Context::new();

    context.insert("title", "Dashboard");
    context.insert("description", "This is the dashboard page");

    let rendered = TEMPLATES.render("dashboard.html", &context).map_err(|e| {
        log::error!("Failed to render template: {}", e);
        AppError::TemplateError(e)
    })?;

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(rendered))
}
