extern crate mio;
extern crate netbuf;
extern crate byteorder;

#[macro_use]
extern crate bitflags;

use std::env;
use mio::{Token, Poll, Ready, PollOpt, Events};
use mio::tcp::TcpStream;
use std::str::FromStr;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr, SocketAddr};
use std::io;
use std::io::{BufReader, BufRead, Write, BufWriter};
use std::fs::File;
use netbuf::Buf;
use mio::unix::UnixReady;
use byteorder::ByteOrder;
use std::collections::HashMap;

enum WhoisQuery {
	Domain(String),
	IpAddr(IpAddr),
	AS(u32),
	Unspecified(String)
}

bitflags! {
	struct IpSupport: u8 {
		const IP_V4 = 1;
		const IP_V6 = 2;
	}
}

struct IpConfig {
	defaultVersion: IpSupport,
	supportedVersions: IpSupport
}

impl WhoisQuery {
	fn new(query : String) -> WhoisQuery {
		let ip = IpAddr::from_str(query.as_str());
		if ip.is_ok() {
			WhoisQuery::IpAddr(ip.unwrap())
		} else {
			let asn = query.parse::<u32>();
			if asn.is_ok() {
				WhoisQuery::AS(asn.unwrap())
			} else {
				WhoisQuery::Domain(query)
			}
		}
	}
}

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
			query : query,
			terminated: false
		}
	}
}

struct WhoisDatabase {
	domain_servers : HashMap<String, String>, // map domain to whois server
	server_ips : HashMap<String, (Vec<Ipv4Addr>, Vec<Ipv6Addr>)> // map whois server name to addresses
}

impl WhoisDatabase {
	fn new(domain_server_file: &String, server_ip_file: &String) -> WhoisDatabase {
		let mut result = WhoisDatabase {
			domain_servers: Default::default(),
			server_ips: Default::default()
		};
		result.read_domain_servers(domain_server_file);
		result.read_server_ips(server_ip_file);
		result
	}

	fn read_domain_servers(&mut self, filename : &String) {
		let reader = BufReader::new(File::open(filename).unwrap());
		for l in reader.lines() {
			let trimmed : String = String::from(l.unwrap());
			if trimmed == String::from("") || trimmed.starts_with("#") {
				continue;
			}
			let mut fields = trimmed.split_whitespace();
			let domain = String::from(fields.next().unwrap()).to_lowercase();
			let server = fields.next().map(|x| String::from(x).to_lowercase());
			if server.is_some() {
				self.domain_servers.insert(domain, server.unwrap());
			}
		}
	}
	
	fn read_server_ips(&mut self, filename : &String) {
		let reader = BufReader::new(File::open(filename).unwrap());
		for l in reader.lines() {
			let trimmed : String = String::from(l.unwrap());
			if trimmed == String::from("") || trimmed.starts_with("#") {
				continue;
			}
			let mut fields = trimmed.split_whitespace();
			let server = String::from(fields.next().unwrap()).to_lowercase();
			let mut ip4_addrs : Vec<Ipv4Addr> = Default::default();
			let mut ip6_addrs : Vec<Ipv6Addr> = Default::default();
			for ip_str in fields {
				let ip = IpAddr::from_str(ip_str).unwrap();
				match ip {
					IpAddr::V4(addr) => ip4_addrs.push(addr),
					IpAddr::V6(addr) => ip6_addrs.push(addr)
				}
			}
			self.server_ips.insert(server, (ip4_addrs, ip6_addrs));
		}
	}

	fn get_server<'a>(&'a self, query : &'a WhoisQuery) -> Option<&'a String> {
		match *query {
			WhoisQuery::Domain(ref x) => 
			{
				let full = self.domain_servers.get(x);
				if full.is_some() {
					return full;
				}
				for (pos, ch) in x.char_indices() {
					if ch == '.' {
						let part = &x.as_str()[pos + 1..];
						println!("{}", part);
						let result = self.domain_servers.get(&String::from(part));
						if result.is_some() {
							return result;
						}
					}
				}
				None
			}
			// TODO: Implement other types
			_ => None
		}
	}

	fn get_server_ip<'a>(&'a self, try: usize, server: Option<&'a String>, ip_conf: &IpConfig) -> Option<IpAddr> {
		if server.is_none() {
			None
		} else{
			let server_str = server.unwrap();
			let ips = self.server_ips.get(server_str);
			if ips.is_some() {
				let &(ref ip4, ref ip6) = ips.unwrap();
				// TODO: Use ip_config and try
				return Some(IpAddr::V4(ip4[0]));
			}
			None
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
	db : WhoisDatabase,
	callback : &'a mut FnMut(&mut WhoisClient)
}

impl<'a> MassWhois<'a> {
	
	fn new(concurrency : usize, reader : &'a mut BufRead, cb: &'a mut FnMut(&mut WhoisClient)) -> Self {
		let poll = Poll::new().expect("Failed to create polling interface.");
		let result = MassWhois {
			concurrency: concurrency,
			servers: Default::default(),
			clients: Vec::with_capacity(concurrency),
			end_reached: Default::default(),
			poll: poll,
			events: Events::with_capacity(concurrency),
			reader: reader,
			//writer: writer,
			running: 0,
			db: WhoisDatabase {
				domain_servers: Default::default(),
				server_ips: Default::default()
			},
			callback: cb
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
							{
								let ref mut stream = client.stream;
								client.inbuf.read_from::<TcpStream>(stream).expect("Failed to read.");
							}
							if UnixReady::from(event.readiness()).is_hup() {
							
								(self.callback)(client);
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
		//self.writer.flush().expect("Failed to flush output file.");
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
	/*let db = WhoisDatabase::new(&String::from("data/domain_servers.txt"), &String::from("data/server_ip.txt"));
	let q = WhoisQuery::Domain(String::from("yolo.example.com"));
	let ip_config = IpConfig {
		defaultVersion: IP_V6,
		supportedVersions: IP_V4 | IP_V6
	};
	let s = db.get_server_ip(0, db.get_server(&q), &ip_config);*/
	
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
	
	let mut print_result = |client : &mut WhoisClient|{
		let query_bytes = client.query.as_bytes();
		let mut buf : [u8; 8] = [0; 8];
		byteorder::LittleEndian::write_u64(&mut buf, query_bytes.len() as u64);
		writer.write(&buf).expect("Write failure");
		writer.write(query_bytes).expect("Write failure");
		byteorder::LittleEndian::write_u64(&mut buf, client.inbuf.len() as u64);
		writer.write(&buf).expect("Write failure");
		writer.write(client.inbuf.as_ref()).expect("Write failure");
	};


	let mut masswhois : MassWhois = MassWhois::new(concurrency, &mut reader, &mut print_result);
	masswhois.servers = servers;
	masswhois.start();
}
