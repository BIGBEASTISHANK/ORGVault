use crate::webServer;
use actix_web::{App, HttpServer, web};
use std::net::Ipv4Addr;

// Global Variables
pub const serverAddress: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
pub const serverPort: u16 = 8080;

// APIEndpoint config function
fn config(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(webServer::webIndex));
}

// Server Main Function
pub async fn serverMain() -> std::io::Result<()> {
    HttpServer::new(|| App::new().configure(config))
        .bind((serverAddress, serverPort))?
        .run()
        .await
}
