#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

mod server;
mod webServer;

fn main() -> std::io::Result<()> {
    // Variable
    let tokioRT = tokio::runtime::Runtime::new().unwrap();

    // Starting feedback
    println!(
        "Starting ORGVault server on {}:{}",
        server::serverAddress,
        server::serverPort
    );

    // Starting Server
    return tokioRT.block_on(server::serverMain());
}
