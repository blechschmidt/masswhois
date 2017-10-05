pub mod query;
pub mod database;
pub mod handler;
pub mod client;

use mio::{Token, Poll, Ready, PollOpt, Events};
use mio::tcp::TcpStream;
use std::net::IpAddr;
use std::collections::LinkedList;
use mio::unix::UnixReady;
use masswhois::query::*;
use masswhois::database::*;
use masswhois::client::*;
use masswhois::handler::*;
use dnsutils::*;
use std::net::Ipv4Addr;

bitflags! {
    pub struct IpVersion: u8 {
        const IP_V4 = 1;
        const IP_V6 = 2;
    }
}

#[derive(Copy, Clone)]
pub struct IpConfig {
    pub default_version: IpVersion,
    pub supported_versions: IpVersion
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum Status {
    Initial, DNS, Referral, Other
}

pub struct MassWhois<'a> {
    concurrency: usize, // Number of concurrent TCP connections
    servers: Vec<IpAddr>,
    running: usize,
    clients: Vec<WhoisClient>,
    end_reached: bool,
    poll: Poll,
    events: Events,
    pub db: WhoisDatabase,
    //callback: &'a mut FnMut(&mut WhoisClient),
    next_query: Box<WhoisRawQuerySupplier>,
    infer_servers: bool,
    pub ip_config: IpConfig,
    output: Box<WhoisHandler>,
    resolver: CachingResolver<'a, usize>,
    infer: bool,
    resolving_names: Vec<String>,
    availability_check: bool
}

impl<'a> MassWhois<'a> {

    pub fn new(concurrency: usize, ip_config: IpConfig, infer_servers: bool, next_query: Box<WhoisRawQuerySupplier>, output: Box<WhoisHandler>, infer: bool, availability_check: bool) -> Self {
        let poll = Poll::new().expect("Failed to create polling interface.");
        let mut result = Self {
            concurrency: concurrency,
            servers: Default::default(),
            clients: Vec::with_capacity(concurrency),
            end_reached: Default::default(),
            poll: poll,
            events: Events::with_capacity(concurrency),
            running: 0,
            db: WhoisDatabase::new(&ip_config),
            next_query: next_query,
            infer_servers: infer_servers,
            ip_config: ip_config,
            output: output,
            resolver: CachingResolver::from_config(ip_config, 1000, 10000, 24 * 60, 60),
            infer: infer,
            resolving_names: Vec::with_capacity(concurrency),
            availability_check: availability_check
        };
        for i in 0..concurrency {
            result.resolving_names.push(String::from(""));
            result.clients.push(WhoisClient::new(i,
                                                 WhoisQuery::Unspecified(String::from("")),
                                                 String::from(""),
                                                 Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                                                 Some(String::from(""))));
        }
        result.resolver.add_to_poll(&mut result.poll, concurrency);
        result
    }

    pub fn start(&mut self) {
        for i in 0..self.concurrency {
            if self.end_reached {
                break;
            }
            self.next_client(i, Status::Initial);
        }
        self.handle_events();
    }

    fn check_termination(&mut self) -> bool {
        self.end_reached && self.running <= 0
    }

    fn handle_events(&mut self) {
        loop {
            self.poll.poll(&mut self.events, None).expect("Failed to poll.");
            let mut terminated_clients: Vec<(usize, Status)> = Default::default();
            let mut resolved : LinkedList<usize> = LinkedList::new();
            for event in self.events.iter() {
                match event.token() {
                    Token(i) => {
                        if i < self.concurrency {
                            let ref mut client : WhoisClient = self.clients[i];
                            if event.readiness().is_readable() {
                                {
                                    let ref mut stream = client.stream;
                                    client.inbuf.read_from::<TcpStream>(stream).expect("Failed to read.");
                                }
                                if UnixReady::from(event.readiness()).is_hup() {
                                    if self.availability_check {
                                        client.availability = self.db.availability(client);
                                    }
                                    self.output.handle(client);
                                    if !client.terminated {
                                        client.terminated = true;
                                        let ref_server = self.db.get_referral_server(client);
                                        let status = if ref_server.is_some() && !self.availability_check {
                                            client.server = ref_server;
                                            client.status = Status::Referral;
                                            Status::Referral
                                        } else {
                                            Status::Other
                                        };

                                        // TODO: Find way to call self.next_client here directly
                                        // Maybe use #inline macro?
                                        terminated_clients.push((i, status));
                                    }
                                }
                            } else if event.readiness().is_writable() {
                                let ref mut stream = client.stream;
                                client.outbuf.write_to::<TcpStream>(stream).expect("Failed to write.");
                            }
                        } else { // DNS response
                            let mut handle = |tk: usize| {
                                resolved.push_back(tk);
                            };
                            self.resolver.receive(i, &mut handle);
                        }
                    }
                }
            }

            for c in terminated_clients.iter() {
                self.next_client(c.0, c.1);
            }

            for tk in resolved.iter() {
                self.next_client(*tk, Status::DNS);
            }

            if self.check_termination() {
                break;
            }
        }
    }

    fn next_client(&mut self, i: usize, status: Status) {
        if status != Status::Initial {
            self.running = self.running - 1;
        }
        let orig_str = if status != Status::DNS && status != Status::Referral {
            match self.next_query.get() {
                None => {
                    self.end_reached = true;
                    return;
                },
                Some(s) => s
            }
        } else {
            self.resolving_names[i].clone()
        };

        let query = WhoisQuery::new(orig_str.clone(), !self.infer);

        let mut server = None;
        let (server_name, query_str) = if status != Status::Referral && self.clients[i].status != Status::Referral {
            self.db.get_server(&query)
        } else {
            (self.clients[i].server.clone(), query.to_string())
        };

        self.running = self.running + 1;
        if server_name.is_some() {
            match self.resolver.query(String::from(server_name.clone().unwrap()), i, status == Status::DNS) {
                ResolvePromise::Resolving => {
                    self.resolving_names[i] = orig_str;
                    return;
                },
                ResolvePromise::Resolved(_, None) => {
                    // TODO: Handle properly
                    return;
                },
                ResolvePromise::Resolved(_, Some(ip)) => {
                    server = Some(ip);
                    self.clients[i].status = Status::Initial;
                }
            }
        }
        if !self.infer_servers || server.is_none() {
            if self.servers.len() > 0 {
                server = Some(self.servers[i % self.servers.len()])
            } else {
                server = None
            }
        };

        let client: WhoisClient = WhoisClient::new(i, query, query_str, server, server_name);
        let events = Ready::readable() | Ready::writable() | UnixReady::hup() | UnixReady::error();
        self.poll.register(&client.stream, client.token, events, PollOpt::edge())
            .expect("Failed to register poll.");
        self.clients[i] = client;
        let ref mut client = self.clients[i];
        let inbuf_len = client.inbuf.len();
        client.inbuf.consume(inbuf_len);
        let outbuf_len = client.inbuf.len();
        client.outbuf.consume(outbuf_len);
    }
}
