extern crate byteorder;
extern crate mio;
extern crate netbuf;

use std::io::{BufRead, Write};
use byteorder::ByteOrder;
use masswhois::client::*;
use std::str::Lines;
use std::collections::VecDeque;
use std::str::FromStr;

pub trait WhoisHandler {
    fn handle(&mut self, client: &mut WhoisClient);
}

pub struct WhoisOutputBinary {
    pub writer: Box<Write>
}

impl WhoisHandler for WhoisOutputBinary {
    fn handle(&mut self, client: &mut WhoisClient) {
        let query_str = client.query.to_string();
        let query_bytes = query_str.as_bytes();
        let mut buf: [u8; 8] = [0; 8];
        byteorder::LittleEndian::write_u64(&mut buf, query_bytes.len() as u64);
        self.writer.write(&buf).expect("Write failure");
        self.writer.write(query_bytes).expect("Write failure");
        byteorder::LittleEndian::write_u64(&mut buf, client.inbuf.len() as u64);
        self.writer.write(&buf).expect("Write failure");
        self.writer.write(client.inbuf.as_ref()).expect("Write failure");
    }
}

pub struct WhoisOutputReadable {
    pub writer: Box<Write>
}

impl WhoisHandler for WhoisOutputReadable {
    fn handle(&mut self, client: &mut WhoisClient) {
        self.writer.write("----- ".as_bytes()).expect("Write failure");
        self.writer.write(client.query.to_string().as_bytes()).expect("Write failure");
        self.writer.write(" -----\n\n".as_bytes()).expect("Write failure");
        self.writer.write(client.inbuf.as_ref()).expect("Write failure");
        self.writer.write("\n\n".as_bytes()).expect("Write failure");
    }
}

pub trait WhoisRawQuerySupplier {
    fn get(&mut self) -> Option<String>;
}

pub struct WhoisRawQueryReader {
    reader: Box<BufRead>
}

impl WhoisRawQueryReader {
    pub fn new(reader: Box<BufRead>) -> Self {
        Self {
            reader: reader
        }
    }
}

impl WhoisRawQuerySupplier for WhoisRawQueryReader {
    fn get(&mut self) -> Option<String> {
        let mut line: String = Default::default();
        if self.reader.read_line(&mut line).expect("Failed to read line") <= 0 {
            return None;
        }
        let line = String::from(line.trim());
        return Some(line);
    }
}

pub struct WhoisRawQueryCmd {
    lines: VecDeque<String>
}

impl WhoisRawQueryCmd {
    pub fn new(string: String) -> Self {
        let mut lines = VecDeque::new();

        for line in string.lines() {
            lines.push_back(String::from_str(line).unwrap());
        }

        Self {
            lines: lines
        }
    }
}

impl WhoisRawQuerySupplier for WhoisRawQueryCmd {
    fn get(&mut self) -> Option<String> {
        return self.lines.pop_front();
    }
}