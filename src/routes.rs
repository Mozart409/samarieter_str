use actix_identity::Identity;
use db::{create_tenant, create_user};
use serde_json::to_string;

use std::env;
use utils::verify_password;

use actix_files::NamedFile;
use actix_web::{
    get, post,
    web::{self, Data},
    HttpMessage, HttpRequest, HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

use errors::AppError;
use tera::Context;

use crate::{
    db, errors,
    structs::{Tenant, User},
    utils, AppState, TEMPLATES,
};

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
            match verify_password(&form.password, &user_record.pwd_hash) {
                Ok(true) => {
                    // Create (remember) an identity session for the authenticated user
                    Identity::login(&request.extensions(), user_record.id.to_string()).unwrap();

                    return Ok(HttpResponse::Ok().body("Login successful"));
                }
                Ok(false) | Err(_) => {
                    return Ok(HttpResponse::Unauthorized().body("Invalid credentials"));
                }
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
pub async fn logout_handler(user: Identity) -> impl Responder {
    user.logout();
    return HttpResponse::SeeOther()
        .append_header(("Location", "/"))
        .body("Redirecting to home page");
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
pub async fn dashboard_handler(
    state: Data<AppState>,
    identity: Option<Identity>,
) -> Result<impl Responder, AppError> {
    let id = match identity {
        Some(id) => id,
        None => {
            log::warn!("Unauthorized access attempt to dashboard: No identity found.");
            return Ok(HttpResponse::Unauthorized().body("Unauthorized"));
        }
    };

    let user = db::get_user_by_email(&state, id.id().unwrap())
        .await
        .map_err(|e| {
            log::error!("Failed to fetch user by email: {}", e);
            AppError::DatabaseError(e)
        })?;

    let items = db::get_all_items(&state, user.tenant_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get items: {}", e);
            AppError::DatabaseError(e)
        })?;

    let mut context = Context::new();

    context.insert("title", "Dashboard");
    context.insert("description", "This is the dashboard page");
    context.insert("items", &items);

    let rendered = TEMPLATES.render("dashboard.html", &context).map_err(|e| {
        log::error!("Failed to render template: {}", e);
        AppError::TemplateError(e)
    })?;

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(rendered))
}

#[get("/change-pwd")]
pub async fn change_pwd_handler(identity: Option<Identity>) -> Result<impl Responder, AppError> {
    // Check if the user is logged in
    if identity.is_none() {
        // Redirect to login page or return unauthorized response
        return Ok(HttpResponse::SeeOther()
            .append_header(("Location", "/login"))
            .body("Redirecting to login page"));

        // return Ok(HttpResponse::Unauthorized().body("Unauthorized"));
    }

    let mut context = Context::new();

    context.insert("title", "Change Password");
    context.insert("description", "This is the change password page");

    let rendered = TEMPLATES.render("change-pwd.html", &context).map_err(|e| {
        log::error!("Failed to render template: {}", e);
        AppError::TemplateError(e)
    })?;

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(rendered))
}

#[derive(Deserialize)]
pub struct ChangePwdForm {
    old_password: String,
    password: String,
    password2: String,
}

#[post("/change-pwd")]
pub async fn change_pwd_form_handler(
    web::Form(form): web::Form<ChangePwdForm>,
    state: Data<AppState>,
    identity: Option<Identity>,
) -> Result<impl Responder, AppError> {
    // Check if the user is logged in
    if identity.is_none() {
        return Ok(HttpResponse::Unauthorized().body("Unauthorized"));
    }

    // Validate the form data
    if form.old_password.is_empty() || form.password.is_empty() || form.password2.is_empty() {
        return Ok(HttpResponse::BadRequest().body("All fields are required"));
    }
    if form.password != form.password2 {
        return Ok(HttpResponse::BadRequest().body("Passwords do not match"));
    }
    if form.password.len() < 12 {
        return Ok(HttpResponse::BadRequest().body("Password must be at least 12 characters long"));
    }
    if form.password.len() > 128 {
        return Ok(HttpResponse::BadRequest().body("Password must be at most 128 characters long"));
    }

    let user_id = identity
        .unwrap()
        .id()
        .map_err(|e| AppError::IdentityError(e))?;

    // Fetch the user from the database
    let mut conn = state.db_pool.acquire().await.map_err(|e| {
        log::error!("Failed to acquire database connection: {}", e);
        AppError::DatabaseConnectionError(e)
    })?;
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT id, tenant_id, created_at, updated_at, email, pwd_hash
        FROM users
        WHERE id = ?
        "#,
        user_id
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        log::error!("Failed to fetch user: {}", e);
        AppError::DatabaseError(e)
    })?;
    // Verify the old password
    if let Err(e) = utils::verify_password(&form.old_password, &user.pwd_hash) {
        log::warn!("Old password verification failed for user ID: {}", user.id);
        return Ok(HttpResponse::Unauthorized().body("Old password is incorrect"));
    };
    // Hash the new password
    let new_pwd_hash = utils::hash_password(&form.password).map_err(|e| {
        log::error!("Failed to hash new password: {}", e);
        AppError::PasswordError(e.to_string())
    })?;
    // Update the user's password in the database
    db::update_user(
        &state,
        user.id,
        None, // No change to email
        Some(new_pwd_hash),
    )
    .await
    .map_err(|e| {
        log::error!("Failed to update user password: {}", e);
        AppError::PasswordError(e.to_string())
    })?;
    // If everything is successful, redirect to the dashboard
    log::info!("Password changed successfully for user ID: {}", user.id);

    Ok(HttpResponse::SeeOther()
        .append_header(("Location", "/dashboard"))
        .body("Password changed successfully"))
}

#[derive(Deserialize)]
pub struct ItemForm {
    name: String,
    amount: String,
}

#[post("/item/create")]
pub async fn create_item_handler(
    state: Data<AppState>,
    identity: Option<Identity>,
    web::Form(form): web::Form<ItemForm>,
) -> Result<impl Responder, AppError> {
    if identity.is_none() {
        return Ok(HttpResponse::Unauthorized().body("Unauthorized"));
    }

    // Validate the form data
    if form.name.is_empty() || form.amount.is_empty() {
        return Ok(HttpResponse::BadRequest().body("Invalid item data"));
    }

    let user_email = identity
        .unwrap()
        .id()
        .map_err(|e| AppError::IdentityError(e))?;

    log::info!("Creating item for user ID: {}", user_email);

    // get tenant id from user
    let mut conn = state.db_pool.acquire().await.map_err(|e| {
        log::error!("Failed to acquire database connection: {}", e);
        AppError::DatabaseConnectionError(e)
    })?;

    let tenant = sqlx::query_as!(
        Tenant,
        r#"
        SELECT * FROM tenants
        WHERE id = (SELECT tenant_id FROM users WHERE email = ?)
        "#,
        user_email
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        log::error!("Failed to fetch tenant for user {}: {}", user_email, e);
        AppError::DatabaseError(e)
    })?;

    let item = db::create_item(&state, tenant.id, form.name.clone(), form.amount)
        .await
        .map_err(|e| {
            log::error!("Failed to create item: {}", e);
            AppError::DatabaseError(e)
        })?;
    log::info!("Item created successfully: {:?}", item);
    Ok(HttpResponse::SeeOther()
        .append_header(("Location", "/dashboard"))
        .body("Item created successfully"))
}

#[derive(Deserialize)]
pub struct ItemDeleteForm {
    item_id: i64,
    tenant_id: i64,
}

#[post("/item/delete")]
pub async fn delete_item_handler(
    state: Data<AppState>,
    identity: Option<Identity>,
    web::Form(form): web::Form<ItemDeleteForm>,
) -> Result<impl Responder, AppError> {
    if identity.is_none() {
        return Ok(HttpResponse::Unauthorized().body("Unauthorized"));
    }

    db::delete_item(&state, form.tenant_id, form.item_id)
        .await
        .map_err(|e| {
            log::error!("Failed to delete item with ID {}: {}", form.item_id, e);
            AppError::DatabaseError(e)
        })?;

    log::info!("Item with ID {} deleted successfully", form.item_id);

    Ok(HttpResponse::SeeOther()
        .append_header(("Location", "/dashboard"))
        .body("Item deleted successfully"))
}
