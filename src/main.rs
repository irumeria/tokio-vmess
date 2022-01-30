use i2ray::*;
use std::io::Result;
#[tokio::main]
async fn main() -> Result<()> {
    let port = 18001; //  in-bound port
    let proxy_type = "socks"; // in-bound type
    let proxy_dist_socks = "";// here goes the ip:port of vmess proxy server 
    let uuid = ""; // here goes the uuid of vmess proxy server 
    let proxy_dist_http = ""; // ip:port of the dist http proxy server
    println!("address : {},type:{}", "0.0.0.0", proxy_type);

    if proxy_type == "http" {
        // TO DO: HTTP in-bound do not access to vmess out-bound yet
        let http_server = HttpServer::new(port);
        http_server.listen(proxy_dist_http).await?;
    } else if proxy_type == "socks" {
        let socks5_server = Socks5Server::new(port);
        socks5_server.listen(proxy_dist_socks,parse_uid(uuid).unwrap()).await?;
    }
    Ok(())
}

