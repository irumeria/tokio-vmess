use super::*;
use rand::prelude::*;
use std::convert::TryFrom;
use std::{io::Result, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
pub struct HttpServer {
    port: u16,
}

impl HttpServer {
    pub fn new(port: u16) -> HttpServer {
        HttpServer { port }
    }

    pub async fn listen(&self, proxy_dist: String, uuid: [u8; 16]) -> Result<()> {
        let listener = TcpListener::bind(String::from("0.0.0.0:") + &self.port.to_string()).await?;
        let _proxy_dist = Arc::new(proxy_dist);
        loop {
            let _proxy_dist = (*_proxy_dist).clone();
            let (stream, _) = listener.accept().await?;
            tokio::spawn(async move {
                handle_http(stream, _proxy_dist, uuid).await.unwrap();
            });
        }
    }
}
#[allow(non_snake_case)]
async fn handle_http(stream_c: TcpStream, server: String, uuid: [u8; 16]) -> Result<()> {
    let stream_p = TcpStream::connect(server).await?;

    let (mut pread, mut pwrite) = stream_p.into_split();
    let (mut cread, mut cwrite) = stream_c.into_split();

    // get (ip / domain) and port from http req
    let mut pre_buffer = [0; 16384];
    let len_pre = match cread.read(&mut pre_buffer).await {
        Ok(0) => 0,
        Ok(x) => x,
        Err(ref e) if is_normal_close(e) => return Ok(()),
        Err(e) => {
            warn!("{}", e);
            0
        }
    };

    let ibuf = pre_buffer.clone();

    let mut iter = ibuf.iter();
    let mut ib = 0; // begin of whole addr
    let mut ie = 0; // end of whole addr
    let pb; // begin of port
    let port_ignore_flag;
    loop {
        // find "Host:"
        let H_loc = iter.position(|&x| x == 72).unwrap();
        let mut n1 = iter.next().unwrap();
        let n2 = iter.next().unwrap();
        let n3 = iter.next().unwrap();
        if n1 == &111 && n2 == &115 && n3 == &116 {
            iter.next().unwrap();
            iter.next().unwrap();
            ib += H_loc + 9;
            let mut r_loc;
            let sp_loc;
            let mut _iter = iter.clone();

            loop {
                // find the first "\r\n" behind "Host"
                r_loc = iter
                    .position(
                        |&x| x == 13, // \r
                    )
                    .unwrap();
                n1 = iter.next().unwrap();
                if n1 == &10 {
                    // \n
                    break;
                } else {
                    ie += r_loc
                }
            }

            // find ":" that devide the ip and port
            match _iter.position(
                |&x| x == 58, // :
            ) {
                Some(x) => {
                    if x > r_loc {
                        // not the : between ip and port
                        port_ignore_flag = true;
                        sp_loc = r_loc;
                    } else {
                        port_ignore_flag = false;
                        sp_loc = x;
                    }
                }
                None => {
                    port_ignore_flag = true;
                    sp_loc = ie
                }
            }
            ie += r_loc + ib;
            pb = sp_loc + ib;
            break;
        } else {
            ib += H_loc + 1;
        }
    }

    let mut ipbuf;
    let mut portbuf;
    // TO DO: it is not a reliable method when "123.com" appear ...
    match &pre_buffer[ib + 2] {
        91 => {
            // "["
            // ipv6
            // TO DO
            ipbuf = Vec::from(&pre_buffer[ib + 3..ie - 4]);
            portbuf = Vec::from(&pre_buffer[ie - 2..ie]);
        }
        x if x < &97 => {
            //  a number
            // ipv4
            let ipbuf_raw = Vec::from(&pre_buffer[ib..pb]);
            let ip_c = ipbuf_raw.clone();
            let mut iter_ip = ip_c.iter();
            ipbuf = Vec::with_capacity(4);
            let mut last_dot: usize = 0;
            let mut y: u8 = 0;
            for _ in 0..3 {
                // find "."
                let dot = last_dot + iter_ip.position(|&x| x == 46).unwrap();
                if last_dot == 0 {
                    for i in 0..dot - last_dot {
                        y += 10u8.pow(u32::try_from(i).unwrap())
                            * (&ipbuf_raw[(dot - i - 1) as usize] - 48);
                    }
                } else {
                    for i in 0..dot - last_dot {
                        y += 10u8.pow(u32::try_from(i).unwrap())
                            * (&ipbuf_raw[(dot - i - 1) as usize] - 48);
                    }
                }
                ipbuf.push(y);
                y = 0;
                last_dot = dot + 1;
            }
            for i in 0..ipbuf_raw.len() - last_dot {
                y += 10u8.pow(u32::try_from(i).unwrap())
                    * (&ipbuf_raw[(ipbuf_raw.len() - 1 - i) as usize] - 48);
            }
            ipbuf.push(y);
            let mut y: u16 = 0;
            ipbuf = Vec::from(&ipbuf[..]);
            // deal with port
            if port_ignore_flag {
                portbuf = vec![0, 80];
            } else {
                let portbuf_raw = Vec::from(&pre_buffer[pb + 1..ie]);
                for i in 0..portbuf_raw.len() {
                    y += 10u16.pow(u32::try_from(i).unwrap())
                        * (&portbuf_raw[portbuf_raw.len() - 1 - i as usize] - 48) as u16;
                }
                portbuf = Vec::with_capacity(2);
                portbuf.push((y >> 8) as u8);
                portbuf.push(y as u8);
            }

            println!(
                "raw_ip:{:?},string_ip:{:?},ip:{:?},port:{:?}",
                ipbuf_raw,
                String::from_utf8_lossy(&ipbuf_raw),
                &ipbuf,
                &portbuf
            );
        }
        _ => {
            // domain
            // TO DO
            ipbuf = Vec::from(&pre_buffer[ib + 2..ie - 2]);
            portbuf = Vec::from(&pre_buffer[ie - 2..ie + 1]);
        }
    }

    let key = [0; 16].apply(|x| thread_rng().fill_bytes(x));
    let IV = [0; 16].apply(|x| thread_rng().fill_bytes(x));

    tokio::spawn(async move {
        let mut buffer = Box::new([0; 16384]);

        let mut decoder = vmess::AES128CFB::new(md5!(&key), md5!(&IV));
        vmess::handshake_read(&mut pread, &mut decoder)
            .await
            .unwrap();
        loop {
            let len = match vmess::read_data(&mut pread, &mut *buffer, &mut decoder).await {
                Ok(0) => break,
                Ok(x) => x,
                Err(ref e) if is_normal_close(e) => break,
                Err(e) => {
                    warn!("{}", e);
                    break;
                }
            };
            println!("ret_msg:{:?}", String::from_utf8_lossy(&buffer[..len]));
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

    vmess::handshake_write(&mut pwrite, uuid, (ipbuf, portbuf), key, IV)
        .await
        .unwrap();

    println!(
        "per_buffer:{:?}",
        String::from_utf8_lossy(&pre_buffer[..len_pre])
    );
    vmess::write_data(&mut pwrite, &mut encoder, &pre_buffer[..len_pre])
        .await
        .unwrap_or(0); //  write the buffer from the header of client request

    loop {
        let len = match cread.read(&mut *buffer).await {
            Ok(0) => break,
            Ok(x) => x,
            Err(ref e) if is_normal_close(e) => break,
            Err(e) => {
                warn!("{}", e);
                break;
            }
        };
        match vmess::write_data(&mut pwrite, &mut encoder, &buffer[..len]).await {
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
