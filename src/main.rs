use actix_files::{Files, NamedFile};
use actix_web::{
    get,
    http::{Method, StatusCode},
    middleware, web, App, Either, Error, HttpResponse, HttpServer, Responder, ResponseError,
};
use derive_more::Display;
use log::info;

#[derive(Debug, Display)]
pub enum AppError {
    #[display("Forbidden")]
    Forbidden,
    #[display("Unauthorized")]
    Unauthorized,
    #[display("Internal Server")]
    InternalServerError,
    #[display("Bad request")]
    BadRequest,
}

/// Actix Web uses `ResponseError` for conversion of errors to a response
impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::Forbidden => {
                println!("do some stuff related to CustomOne error");
                HttpResponse::Forbidden().finish()
            }

            AppError::Unauthorized => {
                println!("do some stuff related to CustomTwo error");
                HttpResponse::Unauthorized().finish()
            }

            AppError::InternalServerError => {
                println!("do some stuff related to CustomThree error");
                HttpResponse::InternalServerError().finish()
            }

            _ => {
                println!("do some stuff related to CustomFour error");
                HttpResponse::BadRequest().finish()
            }
        }
    }
}

/// favicon handler
#[get("/favicon")]
async fn favicon_handler() -> impl Responder {
    NamedFile::open("static/favicon.ico")
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

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
            .default_service(web::to(default_handler))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
/// index handler
#[get("/")]
async fn index_handler() -> impl Responder {
    NamedFile::open("static/index.html")
}

// async fn index_handler() -> Result<HttpResponse, Error> {
//     Ok(HttpResponse::Ok().body("Index handler"))
// }
