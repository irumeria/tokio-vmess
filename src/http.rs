use super::*;
use std::io::Result;
use tokio::{
    io::{self, AsyncReadExt},
    net::{TcpListener, TcpStream},
    select,
};

pub struct HttpServer {
    port: u16,
}

impl HttpServer {
    pub fn new(port: u16) -> HttpServer {
        HttpServer { port }
    }

    pub async fn listen(&self, proxy_dist: &'static str) -> Result<()> {
        let listener = TcpListener::bind(String::from("0.0.0.0:") + &self.port.to_string()).await?;

        loop {
            let (stream, _) = listener.accept().await?;
            tokio::spawn(async move {
                handle_http(stream, proxy_dist).await.unwrap();
            });
        }
        Ok(())
    }
}

async fn handle_http(client: TcpStream, server: &str) -> Result<()> {

    let server = TcpStream::connect(server).await?;
    tokio::spawn(async move {

        let (mut eread, mut ewrite) = client.into_split();
        let (mut oread, mut owrite) = server.into_split();
        
        // 先检查下是不是http
        let mut buffer = [0; 128];

        println!("eread before:{:?}",eread);

        eread.read(&mut buffer).await.unwrap_or(0);

        let input = String::from_utf8_lossy(&buffer[..]);
        let mut vec = input.lines();

        let header = vec.next().unwrap();
        let mut header_split = header.split(' ');
        let func = header_split.next().unwrap_or("none").to_string(); // GET
        let url = header_split.next().unwrap_or("none"); // 请求url
        let prot = header_split.next().unwrap_or("none").split('/').next().unwrap_or("none"); // HTTP
        if url == "none" || func == "none" || prot != "HTTP"{
            warn!("not a http message");
            return ();
        }     

        owrite.try_write(&buffer).unwrap_or(0);

        let e2o = tokio::spawn(async move { io::copy(&mut eread, &mut owrite).await });
        let o2e = tokio::spawn(async move { io::copy(&mut oread, &mut ewrite).await });

        select! {
            _ = e2o => println!("c2s done"),
            _ = o2e => println!("s2c done"),

        }
    });
    Ok(())

}
