pub mod query;
pub mod database;
pub mod handler;
pub mod client;

use mio::{Token, Poll, Ready, PollOpt, Events};
use mio::tcp::TcpStream;
use std::net::IpAddr;
use mio::unix::UnixReady;
use masswhois::query::*;
use masswhois::database::*;
use masswhois::client::*;
use masswhois::handler::*;

bitflags! {
    pub struct IpVersion: u8 {
    const IP_V4 = 1;
    const IP_V6 = 2;
    }
}

pub struct IpConfig {
    pub default_version: IpVersion,
    pub supported_versions: IpVersion
}

pub struct MassWhois<'a> {
    concurrency : usize, // Number of concurrent TCP connections
    servers : Vec<IpAddr>,
    running: usize,
    clients: Vec<WhoisClient>,
    end_reached : bool,
    poll : Poll,
    events : Events,
    pub db : WhoisDatabase,
    //callback : &'a mut FnMut(&mut WhoisClient),
    next_query: &'a mut FnMut() -> Option<WhoisQuery>,
    infer_servers : bool,
    pub ip_config : IpConfig,
    output: Box<WhoisHandler>
}

impl<'a> MassWhois<'a> {
    pub fn new(concurrency : usize, ip_config: IpConfig, infer_servers : bool, next_query: &'a mut FnMut() -> Option<WhoisQuery>, output: Box<WhoisHandler>) -> Self {
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

    pub fn start(&mut self) {
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
