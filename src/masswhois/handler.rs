extern crate byteorder;
extern crate mio;
extern crate netbuf;

use std::io::Write;
use byteorder::ByteOrder;
use masswhois::client::*;

pub trait WhoisHandler {
    fn handle(&mut self, client: &mut WhoisClient);
}

pub struct WhoisOutputBinary {
    pub writer: Box<Write>
}

impl WhoisHandler for WhoisOutputBinary {
    fn handle(&mut self, client: &mut WhoisClient) {
        let query_bytes = client.query.as_bytes();
        let mut buf : [u8; 8] = [0; 8];
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
        self.writer.write(client.query.as_bytes()).expect("Write failure");
        self.writer.write(" -----\n\n".as_bytes()).expect("Write failure");
        self.writer.write(client.inbuf.as_ref()).expect("Write failure");
        self.writer.write("\n\n".as_bytes()).expect("Write failure");
    }
}
