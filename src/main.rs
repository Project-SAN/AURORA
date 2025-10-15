use hornet::api::hello::{hello, manual_hello};
use hornet::api::prove::{PolicyAuthorityState, prove};

use actix_web::{App, HttpServer, web};
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let authority_state = web::Data::new(PolicyAuthorityState::new());
    HttpServer::new(move || {
        App::new()
            .app_data(authority_state.clone())
            .service(hello)
            .service(prove)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
