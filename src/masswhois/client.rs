extern crate mio;
extern crate netbuf;

use mio::Token;
use mio::tcp::TcpStream;
use netbuf::Buf;
use std::net::{IpAddr, SocketAddr};
use std::io::Write;
use masswhois::query::WhoisQuery;
use masswhois::Status;
use std::string::ToString;

pub enum Availability {
    AVAILABLE, UNAVAILABLE, UNKNOWN
}

impl ToString for Availability {
    fn to_string(&self) -> String {
        match *self {
            Availability::AVAILABLE => String::from("AVAILABLE"),
            Availability::UNAVAILABLE => String::from("UNAVAILABLE"),
            _ => String::from("UNKNOWN")
        }
    }
}

pub struct WhoisClient {
    pub stream: TcpStream,
    pub token: Token,
    pub query_str: String,
    pub inbuf: Buf,
    pub outbuf: Buf,
    pub terminated: bool,
    pub dns_tries: usize,
    pub error: bool,
    pub query: WhoisQuery,
    pub referral_count: usize,
    pub server: Option<String>,
    pub address: Option<IpAddr>,
    pub status: Status,
    pub availability: Availability
}

impl WhoisClient {
    pub fn new(concurrency_index: usize, query: WhoisQuery, query_str: String, address: Option<IpAddr>, server: Option<String>) -> Self {
        let addr  = SocketAddr::new(address.expect("Non-IP address not implemented."), 43);
        let stream = TcpStream::connect(&addr).expect("Failed to connect.");
        let mut outbuf = Buf::new();
        outbuf.write_all(query_str.as_bytes()).expect("Failed to write to outfile.");
        outbuf.write_all(String::from("\n").as_bytes()).expect("Failed to write to outfile.");
        WhoisClient {
            stream: stream,
            token: Token(concurrency_index),
            inbuf: Buf::new(),
            outbuf: outbuf,
            query_str: query_str,
            terminated: false,
            dns_tries: 0,
            error: false,
            query: query,
            referral_count: 0,
            server: server,
            address: address,
            status: Status::Initial,
            availability: Availability::UNKNOWN
        }
    }
}
