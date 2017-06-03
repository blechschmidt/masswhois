extern crate mio;
extern crate netbuf;
extern crate byteorder;

use std::env;
use mio::{Token, Poll, Ready, PollOpt, Events};
use mio::tcp::TcpStream;
use std::str::FromStr;
use std::net::{IpAddr, SocketAddr};
use std::io;
use std::io::{BufReader, BufRead, Write, BufWriter};
use std::fs::File;
use netbuf::Buf;
use mio::unix::UnixReady;
use byteorder::ByteOrder;

struct WhoisClient {
	stream: TcpStream,
	token : Token,
	query : String,
	inbuf : Buf,
	outbuf : Buf,
	terminated : bool
}

impl WhoisClient {
	fn new(concurrency_index: usize, query : String, address : Option<IpAddr>) -> Self {
		let addr  = SocketAddr::new(address.expect("Non-IP address not implemented."), 43);
		let stream = TcpStream::connect(&addr).expect("Failed to connect.");
		let mut outbuf = Buf::new();
		outbuf.write_all(query.as_bytes()).expect("Failed to write to outfile.");
		outbuf.write_all(String::from("\n").as_bytes()).expect("Failed to write to outfile.");
		WhoisClient {
			stream: stream,
			token: Token(concurrency_index),
			inbuf: Buf::new(),
			outbuf : outbuf,
			query : query.clone(),
			terminated: false
		}
	}
}

struct MassWhois<'a> {
	concurrency : usize, // Number of concurrent TCP connections
	servers : Vec<IpAddr>,
	running: usize,
	clients: Vec<WhoisClient>,
	end_reached : bool,
	poll : Poll,
	events : Events,
	reader : &'a mut BufRead,
	writer : &'a mut Write
}

impl<'a> MassWhois<'a> {
	fn new(concurrency : usize, reader : &'a mut BufRead, writer : &'a mut Write) -> Self {
		let poll = Poll::new().expect("Failed to create polling interface.");
		let result = MassWhois {
			concurrency: concurrency,
			servers: Default::default(),
			clients: Vec::with_capacity(concurrency),
			end_reached: Default::default(),
			poll: poll,
			events: Events::with_capacity(concurrency),
			reader: reader,
			writer : writer,
			running: 0
		};
		result
	}

	fn start(&mut self) {
		for i in 0..self.concurrency {
			if self.end_reached {
				break;
			}
			self.next_client(i, true);
		}
		self.handle_events();
	}

	fn check_termination(&mut self) -> bool {
		self.end_reached && self.running <= 0
	}

	fn handle_events(&mut self) {
		loop {
			self.poll.poll(&mut self.events, None).expect("Failed to poll.");
			let mut terminated_clients : Vec<usize> = Default::default();
			for event in self.events.iter() {
				match event.token() {
					Token(i) => {
						let ref mut client = self.clients[i];
						if event.readiness().is_readable() {
							let ref mut stream = client.stream;
							client.inbuf.read_from::<TcpStream>(stream).expect("Failed to read.");
							if UnixReady::from(event.readiness()).is_hup() {
							
								let query_bytes = client.query.as_bytes();
								let mut buf : [u8; 8] = [0; 8];
								byteorder::LittleEndian::write_u64(&mut buf, query_bytes.len() as u64);
								self.writer.write(&buf).expect("Write failure");
								self.writer.write(query_bytes).expect("Write failure");
								byteorder::LittleEndian::write_u64(&mut buf, client.inbuf.len() as u64);
								self.writer.write(&buf).expect("Write failure");
								self.writer.write(client.inbuf.as_ref()).expect("Write failure");
								if !client.terminated {
									client.terminated = true;
									// TODO: Find way to call self.next_client here directly
									terminated_clients.push(i);
								}
							}
						}
						else if event.readiness().is_writable() {
							let ref mut stream = client.stream;
							client.outbuf.write_to::<TcpStream>(stream).expect("Failed to write.");
						}
					}
				}
			}
			
			// TODO: Find more performant solution than next_queue
			// (introduced due to borrowing issues when calling next_client within event loop)
			for i in terminated_clients.iter() {
				self.next_client(*i, false);
			}
			if self.check_termination() {
				break;
			}
		}
		self.writer.flush().expect("Failed to flush output file.");
	}

	fn next_client(&mut self, i : usize, initial : bool) {
		let mut line : String = Default::default();
		let line_result = self.reader.read_line(&mut line);
		if !initial {
			self.running = self.running - 1;
		}
		if line_result.expect("Failed to read line.") <= 0 {
			self.end_reached = true;
			return;
		}
		self.running = self.running + 1;
		let client : WhoisClient = WhoisClient::new(i, line, Some(self.servers[i % self.servers.len()]));
		self.poll.register(&client.stream, client.token, Ready::readable() | Ready::writable() | UnixReady::hup() | UnixReady::error(), PollOpt::edge()).expect("Failed to register poll.");
		if initial {
			self.clients.push(client);
		} else {
			self.clients[i] = client;
		}
		let ref mut client = self.clients[i];
		let inbuf_len = client.inbuf.len();
		client.inbuf.consume(inbuf_len);
		let outbuf_len = client.inbuf.len();
		client.outbuf.consume(outbuf_len);
	}
}

fn main() {
	
	let mut args = env::args().skip(1);
	let mut infile : Option<String> = None;
	let mut outfile : Option<String> = None;
	let mut servers : Vec<IpAddr> = Default::default();
	let mut concurrency : usize = 5;
	loop {
		match args.next() {
			Some(x) => match x.as_ref() {
				"-s" | "--server" => {
					let ip_str = args.next().expect("Missing server argument.");
					let ip_addr = IpAddr::from_str(ip_str.as_ref()).expect("Invalid server argument.");
					servers.push(ip_addr)
				},
				"-c" | "--concurrency" => {
					let concurrency_str = args.next().expect("Missing concurrency argument.");
					concurrency = usize::from_str(concurrency_str.as_ref()).expect("Invalid concurrency argument.");
				},
				"-o" | "--outfile" => {
					if outfile.is_some() {
						panic!("Invalid parameter.");
					}
					outfile = Some(args.next().expect("Missing outfile."));
				},
				&_ => {
					if infile.is_some() {
						panic!("Invalid parameter.");
					}
					infile = Some(x);
				}
			},
			None => {
				break;
			}
		}
	}
	let mut reader : Box<BufRead> = if infile == None || infile == Some(String::from("-")) {
		Box::new(BufReader::new(io::stdin()))
	} else {
		Box::new(BufReader::new(File::open(infile.unwrap()).expect("Error opening file.")))
	};
	let mut writer : Box<Write> = if outfile == None || outfile == Some(String::from("-")) {
		Box::new(BufWriter::new(io::stdout()))
	} else {
		Box::new(BufWriter::new(File::create(outfile.unwrap()).expect("Error opening file.")))
	};
	let mut masswhois : MassWhois = MassWhois::new(concurrency, &mut reader, &mut writer);
	masswhois.servers = servers;
	masswhois.start();
}
