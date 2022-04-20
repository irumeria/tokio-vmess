# tokio-vmess
Write a v2ray core for fun
an Asynchronous proxy implement with http / socks5 in-bound and vmess out-bound, written in Rust and tokio

## Config 
```json
{
    "port": 18002,
    "proxy_type" : "socks", 
    "proxy_dist" : "ip:port",
    "uuid" : "uuid of vmess proxy server"
}
```  

## Launch
+ run the code
```bash
$ cargo run ./config.json 
```
+ comile
```bash
$ cargo build --release
```

## Description
+ This program draws from the ylxdzsw's <a href="https://github.com/ylxdzsw/v2socks">v2socks</a> and here rewrite it into an Asynchronous one 
+ Socks5 inbound proxy is done. Http inbound only completes the part where the target server is ipv4. which is tested by cURL:
```bash
$ curl --proxy 127.0.0.1:18002 $destip
````
