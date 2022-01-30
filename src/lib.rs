mod socks;
mod http;
mod vmess;
pub use vmess::*;
pub use http::*;
pub use socks::*;

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {{ eprint!("!!! "); eprintln!($($arg)*) }};
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{ eprint!("  -> "); eprintln!($($arg)*) }};
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {{#[cfg(debug_assertions)]{ eprint!(":: "); eprintln!($($arg)*) }}};
}

use crypto::digest::Digest;

#[macro_export]
macro_rules! md5 {
    ($($x:expr),*) => {{
        let mut digest = crypto::md5::Md5::new();
        let mut result = [0; 16];
        $(digest.input($x);)*
        digest.result(&mut result);
        result
    }}
}