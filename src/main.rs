use i2ray::*;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::Result;
use tokio::fs;

#[derive(Serialize, Deserialize, Clone)]
pub struct ProxyConfig {
    port: u16,          // in-bound port
    proxy_type: String, // in-bound type
    proxy_dist: String, // here goes the ip:port of vmess proxy server
    uuid: String,       // here goes the uuid of vmess proxy server
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path: String;
    let mut args = env::args();
    args.next();
    match args.next() {
        Some(x) => config_path = x.parse().unwrap(),
        None => panic!("need a path of config file "),
    }
    let config = fs::read(config_path).await?;
    let proxy_config: ProxyConfig = serde_json::from_slice(&config)?;

    println!("address : {},type:{}", "0.0.0.0", proxy_config.proxy_type);

    if proxy_config.proxy_type == "http" {
        let http_server = HttpServer::new(proxy_config.port);
        http_server
            .listen(
                proxy_config.proxy_dist,
                parse_uid(&proxy_config.uuid).unwrap(),
            )
            .await?;
    } else if proxy_config.proxy_type == "socks" {
        let socks5_server = Socks5Server::new(proxy_config.port);
        socks5_server
            .listen(
                proxy_config.proxy_dist,
                parse_uid(&proxy_config.uuid).unwrap(),
            )
            .await?;
    }
    Ok(())
}
