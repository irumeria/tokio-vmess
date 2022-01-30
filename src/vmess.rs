use super::*;
use std::vec::Vec;
use std::io::Result;
use crypto::digest::Digest;
use crypto::symmetriccipher::BlockEncryptor;
use crypto::mac::Mac;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf,OwnedWriteHalf}
};
use std::convert::TryInto;

#[derive(Debug)]
pub struct AES128CFB {
    key: [u8; 16],
    state: [u8; 16],
    p: usize,
}

impl AES128CFB {
    #[allow(non_snake_case)]
    pub fn new(key: [u8; 16], IV: [u8; 16]) -> AES128CFB {
        AES128CFB { key, state: IV, p: 16 }
    }

    fn encode(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.p == 16 {
                crypto::aessafe::AesSafe128Encryptor::new(&self.key).encrypt_block(&self.state.clone(), &mut self.state);
                self.p = 0;
            }
            *byte ^= self.state[self.p];
            self.state[self.p] = *byte;
            self.p += 1;
        }
    }

    fn decode(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.p == 16 {
                crypto::aessafe::AesSafe128Encryptor::new(&self.key).encrypt_block(&self.state.clone(), &mut self.state); // yes it's encrypt
                self.p = 0;
            }
            let temp = *byte;
            *byte ^= self.state[self.p];
            self.state[self.p] = temp;
            self.p += 1;
        }
    }
}

// transfer str uuid into array
pub fn parse_uid(x: &str) -> Option<[u8; 16]> {
    let x = x.replace('-', "");
    let list: Vec<_> = (0..32)
      .step_by(2)
      .map(|i| u8::from_str_radix(&x[i..i + 2], 16).unwrap())
      .collect();
  
    let i = list.try_into().ok();
    i     
}
// 1 byte	        1 byte	    1 byte	    1 byte	            M bytes	                The rest
// Response auth V	Option 	    Command 	Command length M	Instruction content	    Actual response data
pub async fn handshake_read(v_read:&mut OwnedReadHalf,decoder:&mut AES128CFB) -> Result<()> {
    let mut head = [0; 4];

    v_read.read_exact(&mut head).await.unwrap();
    decoder.decode(&mut head);

    println!("vmess head:{:?}",head);
    let command_len = head[3] as usize;
    let mut buf = Vec::with_capacity(command_len);
    v_read.read_exact(&mut buf).await?;
    decoder.decode(&mut buf);

    Ok(())
}

pub async fn read_data(v_read:&mut OwnedReadHalf, buf: &mut [u8],decoder:&mut AES128CFB) -> std::io::Result<usize> {
    let mut temp = [0; 4];
    assert!(buf.len() >= (1<<14) - 4);

    // 1. read and decode length
    if let Err(e) = v_read.read_exact(&mut temp[..2]).await {
        match e.kind() {
            // std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset => return Ok(0),
            // _ => return Err(e)
            _=> return Ok(0)
        }
    }
    decoder.decode(&mut temp[..2]);
    let len = (temp[0] as usize) << 8 | temp[1] as usize;

    // 2. read and decode checksum
    v_read.read_exact(&mut temp).await.unwrap();
    decoder.decode(&mut temp);

    // 3. read and decode data
    v_read.read_exact(&mut buf[..len-4]).await.unwrap();
    decoder.decode(&mut buf[..len-4]);

    // 4. verify checksum
    let checksum = fnv1a(&buf[..len-4]);
    if checksum.to_be_bytes() != temp {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid checksum!"))
    }

    Ok(len-4)
}

#[allow(non_snake_case)]
pub async fn handshake_write(v_write :&mut OwnedWriteHalf, user_id: [u8; 16], (ip,port ):( Vec<u8>,Vec<u8>), key: [u8; 16], IV: [u8; 16]) -> std::io::Result<()> {
    let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs().to_be_bytes();
    let mut hmac = crypto::hmac::Hmac::new(crypto::md5::Md5::new(), &user_id);
    hmac.input(&time);
    let mut auth = [0; 16];
    hmac.raw_result(&mut auth);
    v_write.write_all(&auth).await?;

    let mut buffer = Vec::new();

    let version = 1;
    buffer.push(version);

    buffer.extend_from_slice(&IV);
    buffer.extend_from_slice(&key);

    let V = 39; // should be random but who bother
    buffer.push(V);

    let opt = 0b0000_0001;
    buffer.push(opt);

    const P_LEN: u8 = 0;
    let sec = 0; // AES-128-CFB
    buffer.push((P_LEN << 4) | (sec & 0x0f));

    let rev = 0; // reserved
    buffer.push(rev);

    let cmd = 1; // tcp
    buffer.push(cmd);

    buffer.extend_from_slice(&port);

    match ip.len() {
        4 => {
            buffer.push(1);
            buffer.extend_from_slice(&ip);
        }
        16 => {
            buffer.push(3);
            buffer.extend_from_slice(&ip);
        }
        _ => {
            println!("invaild ip length:{:?}",ip.len());
        }
    } 
    let P = [0; P_LEN as usize];
    buffer.extend_from_slice(&P);

    let F = fnv1a(&buffer);
    buffer.extend_from_slice(&F.to_be_bytes());

    // ?
    let header_key = md5!(&user_id, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let header_IV = md5!(&time, &time, &time, &time);

    AES128CFB::new(header_key, header_IV).encode(&mut buffer);

    v_write.write_all(&buffer).await
}

pub async fn write_data(v_write :&mut OwnedWriteHalf, encoder: &mut AES128CFB,data: &[u8]) -> std::io::Result<usize> {
    let len = data.len() + 4;
    let mut buf = Vec::with_capacity(len + 2);
    buf.extend_from_slice(&(len as u16).to_be_bytes());
    buf.extend_from_slice(&fnv1a(data).to_be_bytes());
    buf.extend_from_slice(data);
    encoder.encode(&mut buf); // ?
    v_write.write_all(&buf).await?;
    Ok(data.len())
}

#[allow(clippy::unreadable_literal)]
fn fnv1a(x: &[u8]) -> u32 {
    let prime = 16777619;
    let mut hash = 0x811c9dc5;
    for byte in x.iter() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(prime);
    }
    hash
}
