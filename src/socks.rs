use super::*;
use byteorder::{BigEndian, ByteOrder};
use rand::prelude::*;
use std::io::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};


pub struct Socks5Server {
    port: u16,
}


impl Socks5Server {
    pub fn new(port: u16) -> Socks5Server {
        Socks5Server { port }
    }

    pub async fn listen(&self, proxy_dist:String,uuid: [u8; 16]) -> Result<()> {
        let listener = TcpListener::bind(String::from("0.0.0.0:") + &self.port.to_string()).await?;
        let _proxy_dist = Arc::new(proxy_dist);
        loop {
            let _proxy_dist = (*_proxy_dist).clone();
            let (stream, _) = listener.accept().await?;
            tokio::spawn(async move {
                handle_socks(stream, _proxy_dist,uuid).await.unwrap();
            });
        }
    }
}

#[allow(dead_code)]
async fn copy<'a, T: AsyncRead + Unpin, U: AsyncWrite + Unpin>(sk1: &'a mut T, sk2: &'a mut U) {
    let mut buf = [0; 1024];
    loop {
        let len = sk1.read(&mut buf[..]).await;
        if let Err(err) = len {
            warn!("copy: read error: {:?}", err);
            break;
        }

        let len = len.unwrap();
        if len == 0 {
            break;
        }

        match sk2.write_all(&buf[..len]).await {
            Err(err) => {
                warn!("copy: write error: {:?}", err);
                break;
            }
            _ => {}
        }
    }
}

fn decode_atyp(atyp: u8, len: usize, buf: &[u8; 1024]) -> Result<(String, Vec<u8>, Vec<u8>)> {
    let addr;
    let ipbuf;
    let portbuf;
    let error_ret = (String::from("NULL"), vec![0], vec![0]);
    match atyp {
        1 => {
            if len != 10 {
                warn!("invalid proto");
                return Ok(error_ret);
            }
            ipbuf = Vec::from([buf[4], buf[5], buf[6], buf[7]]);
            portbuf = Vec::from(&buf[8..10]);

            let dst_addr = IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]));
            let dst_port = BigEndian::read_u16(&buf[8..]);
            addr = SocketAddr::new(dst_addr, dst_port).to_string();
        }
        3 => {
            let offset = 4 + 1 + (buf[4] as usize);
            if offset + 2 != len {
                warn!("invalid proto");
                return Ok(error_ret);
            }
            ipbuf = Vec::from(&buf[5..offset]);
            portbuf = Vec::from(&buf[offset..offset+2]);
            let dst_port = BigEndian::read_u16(&buf[offset..]);
            let mut dst_addr = std::str::from_utf8(&buf[5..offset]).unwrap().to_string();
            dst_addr.push_str(":");
            dst_addr.push_str(&dst_port.to_string());
            addr = dst_addr;
        }
        4 => {
            if len != 22 {
                warn!("invalid proto");
                return Ok(error_ret);
            }
            ipbuf = Vec::from(&buf[4..20]);
            portbuf = Vec::from(&buf[20..22]);
            let dst_addr = IpAddr::V6(Ipv6Addr::new(
                ((buf[4] as u16) << 8) | buf[5] as u16,
                ((buf[6] as u16) << 8) | buf[7] as u16,
                ((buf[8] as u16) << 8) | buf[9] as u16,
                ((buf[10] as u16) << 8) | buf[11] as u16,
                ((buf[12] as u16) << 8) | buf[13] as u16,
                ((buf[14] as u16) << 8) | buf[15] as u16,
                ((buf[16] as u16) << 8) | buf[17] as u16,
                ((buf[18] as u16) << 8) | buf[19] as u16,
            ));

            let dst_port = BigEndian::read_u16(&buf[20..]);
            addr = SocketAddr::new(dst_addr, dst_port).to_string();
        }
        _ => {
            warn!("Address type not supported, type={}", atyp);
            return Ok(error_ret);
        }
    }
    info!("incoming socket, request upstream: {:?}", addr);
    Ok((addr, ipbuf, portbuf))
}

async fn handle_socks(mut stream: TcpStream, server: String,uuid: [u8; 16]) -> Result<()> {
    let mut buf = [0; 1024];

    let len = stream.read(&mut buf).await?;

    // socks5: first handshake begin
    if 1 + 1 + (buf[1] as usize) != len || buf[0] != b'\x05' {
        warn!("invalid header");
        return Ok(());
    }
    stream.write_all(b"\x05\x00").await?; // version 5, method 0

    // socks5: first handshake begin
    let len = stream.read(&mut buf).await?;
    if len <= 4 {
        warn!("invalid proto");
        return Ok(());
    }

    let ver = buf[0]; // version
    let cmd = buf[1]; // command code 1-connect 2-bind 3-udp forward
    let atyp = buf[3]; // type of the dist server 1-ipv4 3-domain 4-ipv6

    if ver != b'\x05' {
        warn!("invalid proto");
        return Ok(());
    }

    if cmd != 1 {
        warn!("Command not supported");
        stream
            .write_all(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            .await?;
        return Ok(());
    }

    let (addr, ipbuf, portbuf) = decode_atyp(atyp, len, &buf).unwrap();

    vmess_proxy(stream, &server, (addr, ipbuf, portbuf),uuid).await?;

    Ok(())
}

#[allow(non_snake_case)]
async fn vmess_proxy(
    mut stream_c: TcpStream,
    server: &str,
    (addr, ipbuf, portbuf): (String, Vec<u8>, Vec<u8>),
    uuid: [u8; 16],
) -> Result<()> {
    let stream_p = TcpStream::connect(&server).await?;
    debug!("connect {} through proxy", &addr);
    println!("{:?},{:?}",ipbuf,portbuf);
    let proxy_info = stream_p.local_addr()?; 

    let proxy_port = proxy_info.port();

    println!("addr info :{:?}{:?}",ipbuf,portbuf);
    let mut reply = Vec::with_capacity(22); // cover V4 and V6
    reply.extend_from_slice(&[5, 0, 0]);

    match proxy_info.ip() {
        std::net::IpAddr::V4(x) => {
            let ipbuf_p = x.octets();
            reply.push(1);
            reply.extend_from_slice(&ipbuf_p);
        }
        std::net::IpAddr::V6(x) => {
            let ipbuf_p = x.octets();
            reply.push(4);
            reply.extend_from_slice(&ipbuf_p);
        }
    };

    reply.push((proxy_port >> 8) as u8);
    reply.push(proxy_port as u8);

    stream_c.write(&reply).await?; // socks: second handshake end

    let key = [0; 16].apply(|x| thread_rng().fill_bytes(x));
    let IV = [0; 16].apply(|x| thread_rng().fill_bytes(x));

    let (mut pread, mut pwrite) = stream_p.into_split();
    let (mut cread, mut cwrite) = stream_c.into_split();
    tokio::spawn(async move{
        let mut buffer = Box::new([0; 16384]);

        let mut decoder = vmess::AES128CFB::new(md5!(&key), md5!(&IV));
        vmess::handshake_read(&mut pread,&mut decoder).await.unwrap();
        loop{
            let len = match vmess::read_data(&mut pread,&mut *buffer,&mut decoder).await{
                Ok(0) => break,
                Ok(x) => {
                    x
                },
                Err(ref e) if is_normal_close(e) => break,
                Err(e) => {
                    warn!("{}", e);
                    break;
                }
            };     
            match cwrite.write_all(&buffer[..len]).await {
                Ok(_) => debug!("read {} bytes", len),
                Err(ref e) if is_normal_close(e) => break,
                Err(e) => {
                    warn!("{}", e);
                    break;
                }
            }    
        }
        
        debug!("closed reading")
    });

    let mut encoder = vmess::AES128CFB::new(key, IV);
    let mut buffer = Box::new([0; 16384]);
    
    vmess::handshake_write(&mut pwrite,uuid,(ipbuf, portbuf), key, IV).await.unwrap();
    loop{
        let len = match cread.read(&mut *buffer).await{
            Ok(0) => break,
            Ok(x) => x,
            Err(ref e) if is_normal_close(e) => break,
            Err(e) => {
              warn!("{}", e);
              break;
            }   
        };
        match vmess::write_data(&mut pwrite,&mut encoder,&buffer[..len]).await{
            Ok(_) => debug!("sent {} bytes", len),
            Err(ref e) if is_normal_close(e) => break,
            Err(e) => {
              warn!("{}", e);
              break;
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
async fn plain_proxy(mut stream: TcpStream, addr: String) -> Result<()> {
    let up_stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Upstream connect failed, {}", e);
            stream
                .write_all(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                .await?;
            return Ok(());
        }
    };

    stream
        .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        .await?;

    let (mut ri, mut wi) = stream.into_split();
    let (mut ro, mut wo) = up_stream.into_split();

    tokio::spawn(async move {
        copy(&mut ro, &mut wi).await;
    });

    copy(&mut ri, &mut wo).await;
    return Ok(());
}
