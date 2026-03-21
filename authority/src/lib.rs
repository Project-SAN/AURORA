use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

#[get("/")]
pub async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, World!")
}

#[get("/metadata")]
pub async fn metadata() -> impl Responder {
    HttpResponse::Ok().body("Metadata endpoint")
}
