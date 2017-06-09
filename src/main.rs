extern crate mio;
extern crate netbuf;
extern crate byteorder;

#[macro_use]
extern crate bitflags;

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
use std::collections::HashMap;

static SERVER_ARIN: &'static str = "whois.arin.net";
static SERVER_VERISIGN: &'static str = "whois.verisign-grs.com";
static SERVER_IANA: &'static str = "whois.iana.org";

enum WhoisQuery {
	Domain(String),
	IpAddr(IpAddr),
	AS(u32),
	Unspecified(String)
}

bitflags! {
	struct IpVersion: u8 {
		const IP_V4 = 1;
		const IP_V6 = 2;
	}
}

struct IpConfig {
	default_version: IpVersion,
	supported_versions: IpVersion
}

impl WhoisQuery {
	fn new(query : String, unspecified : bool) -> WhoisQuery {
		if unspecified {
			WhoisQuery::Unspecified(query)
		} else {
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

	// Some servers do not automatically recognize the input type
	// We have to help them by mapping server name to query
	fn construct_query(&self, server : &str) -> String {
		 match *self {
			 WhoisQuery::Domain(ref domain) => {
				let mut result = if server == SERVER_VERISIGN {
					String::from("domain ")
				} else {
					String::from("")
				};
				result.push_str(domain.as_str());
				result
			 },
			 WhoisQuery::IpAddr(addr) => {
				 addr.to_string()
			 },
			 WhoisQuery::AS(asn) => {
				 asn.to_string()
			 },
			 WhoisQuery::Unspecified(ref unspec) => {
				 unspec.clone()
			 }
		 }
	}
}

impl ToString for WhoisQuery {
	fn to_string(&self) -> String {
		match *self {
			WhoisQuery::Domain(ref x) => {
				x.clone()
			},
			WhoisQuery::IpAddr(x) => {
				x.to_string()
			},
			WhoisQuery::AS(x) => {
				x.to_string()
			},
			WhoisQuery::Unspecified(ref x) => {
				x.clone()
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
	server_ips : HashMap<String, Vec<IpAddr>>, // map whois server name to addresses
}

impl WhoisDatabase {
	fn new() -> WhoisDatabase {
		let result = WhoisDatabase {
			domain_servers: Default::default(),
			server_ips: Default::default()
		};
		//result.read_domain_servers(domain_server_file);
		//result.read_server_ips(server_ip_file);
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
	
	fn read_server_ips(&mut self, filename : &String, ip_config : &IpConfig) {
		let reader = BufReader::new(File::open(filename).unwrap());
		for l in reader.lines() {
			let trimmed : String = String::from(l.unwrap());
			if trimmed == String::from("") || trimmed.starts_with("#") {
				continue;
			}
			let mut fields = trimmed.split_whitespace();
			let server = String::from(fields.next().unwrap()).to_lowercase();
			let mut ip4_addrs : Vec<IpAddr> = Default::default();
			let mut ip6_addrs : Vec<IpAddr> = Default::default();
			let mut ip_addrs : Vec<IpAddr> = Default::default();
			for ip_str in fields {
				let ip = IpAddr::from_str(ip_str).unwrap();
				match ip {
					IpAddr::V4(addr) => ip4_addrs.push(IpAddr::V4(addr)),
					IpAddr::V6(addr) => ip6_addrs.push(IpAddr::V6(addr))
				}
			}
			if ip_config.default_version == IP_V4 {
				ip_addrs.append(&mut ip4_addrs);
				if !(ip_config.supported_versions & IP_V6).is_empty() {
					ip_addrs.append(&mut ip6_addrs);
				}
			} else if ip_config.default_version == IP_V6 {
				ip_addrs.append(&mut ip6_addrs);
				if !(ip_config.supported_versions & IP_V4).is_empty() {
					ip_addrs.append(&mut ip4_addrs);
				}
			}
			self.server_ips.insert(server, ip_addrs);
		}
	}

	fn get_server<'a>(&'a self, query : &'a WhoisQuery) -> Option<&'a str> {
		match *query {
			WhoisQuery::Domain(ref x) => {
				let mut is_tld = true;
				for (pos, ch) in x.char_indices() {
					if ch == '.' {
						is_tld = false;
						let part = &x.as_str()[pos + 1..];
						let result = self.domain_servers.get(&String::from(part));
						if result.is_some() {
							return Some(result.unwrap().as_str());
						}
					}
				}
				if is_tld {
					return Some(SERVER_IANA);
				}
				None
			}
			// TODO: Implement other types
			_ => None
		}
	}

	fn get_server_ip<'a>(&'a self, try: usize, server: Option<&'a str>) -> Option<IpAddr> {
		if server.is_none() {
			None
		} else{
			let server_str = String::from(server.unwrap());
			let ips = self.server_ips.get(&server_str);
			if ips.is_some() {
				let ips = ips.unwrap();
				if ips.len() > 0 {
					return Some(ips[try % ips.len()]);
				} else {
					return None;
				}
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
	db : WhoisDatabase,
	//callback : &'a mut FnMut(&mut WhoisClient),
	next_query: &'a mut FnMut() -> Option<WhoisQuery>,
	infer_servers : bool,
	ip_config : IpConfig,
	output: Box<WhoisHandler>
}

impl<'a> MassWhois<'a> {	
	fn new(concurrency : usize, ip_config: IpConfig, infer_servers : bool, next_query: &'a mut FnMut() -> Option<WhoisQuery>, output: Box<WhoisHandler>) -> Self {
		let poll = Poll::new().expect("Failed to create polling interface.");
		let result = MassWhois {
			concurrency: concurrency,
			servers: Default::default(),
			clients: Vec::with_capacity(concurrency),
			end_reached: Default::default(),
			poll: poll,
			events: Events::with_capacity(concurrency),
			running: 0,
			db: WhoisDatabase::new(),
			//callback: cb,
			next_query: next_query,
			infer_servers: infer_servers,
			ip_config: ip_config,
			output: output
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
								//(self.callback)(client);
								self.output.handle(client);
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
	}

	fn next_client(&mut self, i : usize, initial : bool) {
		if !initial {
			self.running = self.running - 1;
		}
		let query = (self.next_query)();
		if query.is_none() {
			self.end_reached = true;
			return;
		}

		let query = query.unwrap();
		let mut server_name = None;
		let mut server = if self.infer_servers {
			server_name = self.db.get_server(&query);
			self.db.get_server_ip(0, server_name)
		} else {
			None
		};
		if !self.infer_servers || server.is_none() {
			if self.servers.len() > 0 {
				server = Some(self.servers[i % self.servers.len()])
			} else {
				server = None
			}
		};
		let query_str = if server_name.is_some() {
			query.construct_query(server_name.unwrap())
		} else {
			query.to_string()
		};

		self.running = self.running + 1;
		let client : WhoisClient = WhoisClient::new(i, query_str, server);
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

trait WhoisHandler {
	fn handle(&mut self, client: &mut WhoisClient);
}

struct WhoisOutputBinary {
	writer: Box<Write>
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

struct WhoisOutputReadable {
	writer: Box<Write>
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

fn main() {
	
	let mut args = env::args().skip(1);
	let mut infile : Option<String> = None;
	let mut outfile : Option<String> = None;
	let mut servers : Vec<IpAddr> = Default::default();
	let mut concurrency : usize = 5;
	let mut ip_config = IpConfig {
		supported_versions: IP_V4,
		default_version: IP_V4
	};
	let mut infer_types = true;
	let mut infer_servers = true;
	let mut stdout = false;
	loop {
		match args.next() {
			Some(x) => match x.as_ref() {
				"-s" | "--server" => {
					let ip_str = args.next().expect("Missing server argument.");
					let ip_addr = IpAddr::from_str(ip_str.as_ref()).expect("Invalid server argument. Must be an IP address.");
					servers.push(ip_addr)
				},
				"--no-infer-types" => {
					infer_types = false;
				},
				"--no-infer-servers" => {
					infer_servers = false;
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
				"--ip" => {
					let ip_str = args.next().expect("Missing ip argument.").replace(" ", "");
					// TODO: Use string splitting instead of matching.
					ip_config = match ip_str.as_ref() {
						"4" => {
							IpConfig {
								supported_versions: IP_V4,
								default_version: IP_V4
							}
						},
						"6" => {
							IpConfig {
								supported_versions: IP_V6,
								default_version: IP_V6
							}
						},
						"4,6" => {
							IpConfig {
								supported_versions: IP_V4 | IP_V6,
								default_version: IP_V4
							}
						},
						"6,4" => {
							IpConfig {
								supported_versions: IP_V4 | IP_V6,
								default_version: IP_V6
							}
						},
						&_ => {
							panic!("Invalid IP support argument.");
						}
					};
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
	let writer : Box<Write> = if outfile == None || outfile == Some(String::from("-")) {
		stdout = true;
		Box::new(BufWriter::new(io::stdout()))
	} else {
		Box::new(BufWriter::new(File::create(outfile.unwrap()).expect("Error opening file.")))
	};
	
	let binary_output: Box<WhoisHandler> = if stdout {
		Box::new(WhoisOutputReadable {
			writer: writer
		})
	} else {
		Box::new(WhoisOutputBinary {
			writer: writer
		})

	};

	let mut next_query = || {
		let mut line : String = Default::default();
		if reader.read_line(&mut line).expect("Failed to read line") <= 0 {
			return None;
		}
		let line = String::from(line.trim());
		return Some(WhoisQuery::new(line, !infer_types));
	};

	let mut masswhois : MassWhois = MassWhois::new(concurrency, ip_config, infer_servers, &mut next_query, binary_output);
	masswhois.db.read_domain_servers(&String::from("data/domain_servers.txt"));
	masswhois.db.read_server_ips(&String::from("data/server_ip.txt"), &masswhois.ip_config);
	masswhois.start();
}
