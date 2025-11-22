use actix_files::NamedFile;
use actix_web::HttpRequest;
use std::io;

// Home web page
pub async fn webIndex(_req: HttpRequest) -> io::Result<NamedFile> {
    Ok(NamedFile::open("static/index.html")?)
}
