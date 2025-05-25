#[macro_use]
extern crate lazy_static;
use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use db::{create_tenant, create_user};

use std::{env, str::FromStr};
use tera::Tera;
use utils::verify_password;
mod utils;

use actix_files::{Files, NamedFile};
use actix_web::{
    cookie::Key,
    http::{Method, StatusCode},
    middleware,
    web::{self, Data},
    App, Either, HttpResponse, HttpServer, Responder,
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
mod routes;
use errors::AppError;
use tera::Context;

#[derive(Debug, Clone)]
pub struct AppState {
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
            .service(routes::favicon_handler)
            .service(routes::index_handler)
            .service(routes::dashboard_handler)
            .service(routes::register_handler)
            .service(routes::register_form_handler)
            .service(routes::login_handler)
            .service(routes::login_form_handler)
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
