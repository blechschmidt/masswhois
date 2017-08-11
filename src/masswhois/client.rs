extern crate mio;
extern crate netbuf;

use mio::Token;
use mio::tcp::TcpStream;
use netbuf::Buf;
use std::net::{IpAddr, SocketAddr};
use std::io::Write;

pub struct WhoisClient {
    pub stream: TcpStream,
    pub token: Token,
    pub query: String,
    pub inbuf: Buf,
    pub outbuf: Buf,
    pub terminated: bool,
    pub dns_tries: usize
}

impl WhoisClient {
    pub fn new(concurrency_index: usize, query: String, address: Option<IpAddr>) -> Self {
        let addr  = SocketAddr::new(address.expect("Non-IP address not implemented."), 43);
        let stream = TcpStream::connect(&addr).expect("Failed to connect.");
        let mut outbuf = Buf::new();
        outbuf.write_all(query.as_bytes()).expect("Failed to write to outfile.");
        outbuf.write_all(String::from("\n").as_bytes()).expect("Failed to write to outfile.");
        WhoisClient {
            stream: stream,
            token: Token(concurrency_index),
            inbuf: Buf::new(),
            outbuf: outbuf,
            query: query,
            terminated: false,
            dns_tries: 0
        }
    }
}
