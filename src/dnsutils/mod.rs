pub mod expiry;

extern crate trust_dns;
extern crate mio;

use std::collections::{HashMap, LinkedList, VecDeque};
use std::time::{SystemTime, Duration};
use std::cmp::Eq;
use std::hash::Hash;
use std::io::{BufReader, BufRead};
use std::fs::File;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::rc::Rc;
use masswhois::{IpConfig, IP_V4, IP_V6};
use self::expiry::{ExpiryHandler};
use self::trust_dns::op::{Message, Query};
use self::trust_dns::rr::domain::Name;
use self::trust_dns::rr::record_type::RecordType;
use self::trust_dns::op::header::MessageType;
use self::trust_dns::rr::record_data::RData;
use std::marker::Copy;
use self::trust_dns::serialize::binary::{BinEncoder, BinSerializable};
use mio::{Poll, PollOpt, Token, Ready};
use mio::net::UdpSocket;

use std::io::prelude::*;

enum ExpiryRef<T> {
    Positive(Rc<T>, usize),
    Negative(Rc<T>)
}

impl<T> ExpiryRef<T> {
    pub fn get_rc(&self) -> Rc<T> {
        match self {
            &ExpiryRef::Negative(ref rc) => {
                rc.clone()
            },
            &ExpiryRef::Positive(ref rc, _) => {
                rc.clone()
            }
        }
    }

    pub fn is_negative(&self) -> bool {
        match self {
            &ExpiryRef::Negative(_) => {
                true
            },
            &ExpiryRef::Positive(_, _) => {
                false
            }
        }
    }

    pub fn is_positive(&self) -> bool {
        !self.is_negative()
    }

    pub fn get_index(&self) -> usize {
        match self {
            &ExpiryRef::Positive(_, size) => {
                size
            },
            _ => {
                panic!("ExpiryRef not positive.");
            }
        }
    }
}

pub enum ResolvePromise<T> {
    Resolved(T, Option<IpAddr>),
    Resolving
}

pub enum RoundRobin {
    None,
    Rotate,
    Random
}

pub struct CachingResolver<'a, T> {
    resolving: HashMap<(String, RecordType), (LinkedList<T>, usize)>,
    encoding: HashMap<String, &'a String>, // 0x20 encoding
    socket4: Option<UdpSocket>,
    socket6: Option<UdpSocket>,
    servers: Vec<SocketAddr>,
    cache4: Option<Cache<String, IpAddr>>,
    cache6: Option<Cache<String, IpAddr>>,
    resolve_parallel: bool,
    ip_config: IpConfig,
    bufvec: Vec<u8>,
    round_robin: RoundRobin,
    round_robin_index: usize,
    epoll_start_token: Option<usize>,
    inbuf: [u8; 0xFFFF]
}

impl<'a, T: Copy> CachingResolver<'a, T> {
    pub fn new(ip_config: IpConfig, capacity: usize, cache_capacity: usize,
               expiry_bucket_count: usize, expiry_bucket_secs: usize) -> Self {
        let mut result = CachingResolver {
            resolving: HashMap::with_capacity(capacity),
            encoding: HashMap::with_capacity(capacity),
            servers: Vec::new(),
            socket4: None,
            socket6: None,
            cache4: None,
            cache6: None,
            resolve_parallel: true,
            ip_config: ip_config,
            bufvec: Vec::with_capacity(0xFFFF),
            round_robin: RoundRobin::None,
            round_robin_index: 0,
            epoll_start_token: None,
            inbuf: [0; 0xFFFF]
        };

        if !(result.ip_config.supported_versions & IP_V4).is_empty() {
            let ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
            result.socket4 = Some(UdpSocket::bind(&SocketAddr::new(ip, 0)).unwrap());
            result.cache4 = Some(Cache::new(cache_capacity, expiry_bucket_count, expiry_bucket_secs));
        }
        if !(result.ip_config.supported_versions & IP_V6).is_empty() {
            let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
            result.socket6 = Some(UdpSocket::bind(&SocketAddr::new(ip, 0)).unwrap());
            result.cache6 = Some(Cache::new(cache_capacity, expiry_bucket_count, expiry_bucket_secs));
        }

        result
    }

    pub fn construct_query(qname: &String, qtype: RecordType, id: u16) -> Message {
        let mut msg = Message::new();
        let mut query = Query::new();
        let mut labels : Vec<String> = qname.split(".").map(|v : &str| String::from(v)).collect();
        labels.pop();
        let name = Name::with_labels(labels);
        query.set_query_type(qtype);
        query.set_name(name);
        msg.set_id(id);
        msg.set_recursion_desired(true);
        msg.set_message_type(MessageType::Query);
        msg.add_query(query);
        msg
    }

    fn get_caches(&mut self) -> (Option<&mut Cache<String, IpAddr>>, Option<&mut Cache<String, IpAddr>>) {
        let secondary_cache;
        let preferred_cache = if self.ip_config.default_version == IP_V4 {
            secondary_cache = self.cache6.as_mut();
            self.cache4.as_mut()
        } else {
            secondary_cache = self.cache4.as_mut();
            self.cache6.as_mut()
        };
        (preferred_cache, secondary_cache)
    }

    fn send_query(mut bufvec: &mut Vec<u8>, qname: &String, qtype: RecordType, sock: &mut UdpSocket, to: &SocketAddr, id: u16) {
        bufvec.clear();
        let msg = CachingResolver::<T>::construct_query(&qname, qtype, id);
        sock.send_to(msg.to_vec().unwrap().as_slice(), to);
    }

    pub fn query(&mut self, mut qname: String, token: T, expect_response: bool) -> ResolvePromise<T> {
        if !qname.ends_with(".") {
            qname.push('.');
        }
        println!("Query: {}", qname.clone());
        let cache_query = self.query_from_cache(&qname, RecordType::A, token, expect_response);
        let mut in_cache = true;
        match cache_query {
            ResolvePromise::Resolving => {
                in_cache = false;
            },
            _ => {}
        }
        if !in_cache && !(IP_V4 & self.ip_config.supported_versions).is_empty() {
            CachingResolver::<T>::send_query(&mut self.bufvec, &qname, RecordType::A, self.socket4.as_mut().unwrap(), &self.servers[0], 10);
        }
        if !in_cache && !(IP_V6 & self.ip_config.supported_versions).is_empty() {
            CachingResolver::<T>::send_query(&mut self.bufvec, &qname, RecordType::AAAA, self.socket4.as_mut().unwrap(), &self.servers[0], 10);
        }
        cache_query
    }

    pub fn add_to_poll(&mut self, poll: &mut Poll, start_token: usize) -> usize {
        let mut added = 0;
        self.epoll_start_token = Some(start_token);
        if self.socket4.is_some() {
            poll.register(self.socket4.as_mut().unwrap(), Token(start_token + added), Ready::readable(), PollOpt::edge());
            added += 1;
        }
        if self.socket6.is_some() {
            poll.register(self.socket6.as_mut().unwrap(), Token(start_token + added), Ready::readable(), PollOpt::edge());
            added += 1;
        }
        added
    }

    pub fn receive(&mut self, token: usize, fun: &mut FnMut (T)) {
        let mut recv;
        if Some(token) == self.epoll_start_token {
            recv = self.socket4.as_mut().unwrap().recv_from(&mut self.inbuf);
        } else if Some(token - 1) == self.epoll_start_token {
            recv = self.socket6.as_mut().unwrap().recv_from(&mut self.inbuf);
        } else {
            return;
        }
        if recv.is_err() {
            return;
        }
        let recv = recv.unwrap();
        let msg = Message::from_vec(&self.inbuf[0..recv.0]);
        if msg.is_err() {
            return;
        }
        let msg = msg.unwrap();
        let queries = msg.queries();
        if queries.len() != 1 {
            return;
        }
        let qname = queries[0].name().to_string();
        let qtype = queries[0].query_type();
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            return;
        }

        let mut res = self.resolving.remove(&(qname, qtype));
        println!("New resolving size {}", self.resolving.len());

        for answer in msg.answers() {
            if answer.rr_type() != qtype {
                continue;
            }
            if let (Some(ref mut cache4), &RData::A(ip4)) = (self.cache4.as_mut(), answer.rdata()) {
                let name = answer.name().to_string();
                cache4.insert(name, IpAddr::V4(ip4), Duration::from_secs(answer.ttl() as u64));
            } else if let (Some(ref mut cache6), &RData::AAAA(ip6)) = (self.cache6.as_mut(), answer.rdata()) {
                cache6.insert(answer.name().to_string(), IpAddr::V6(ip6), Duration::from_secs(answer.ttl() as u64));
            }
        }

        match res {
            None => {
                return;
            },
            Some((ref mut list, _)) => {
                'l: loop {
                    match list.pop_front() {
                        None => {
                            break 'l;
                        },
                        Some(tk) => {
                            fun(tk);
                        }
                    }
                }
            }
        }
    }

    /*pub fn resolved((qname, qtype): (String, RecordType), fun: &'a mut FnMut()) -> Option<String, RecordType> {

    }*/

    fn query_from_cache(&mut self, qname: &String, qtype: RecordType, token: T, expect_response: bool) -> ResolvePromise<T> {
        println!("Query from cache");
        println!("Resolving size {}", self.resolving.len());
        /*let entry = self.resolving.entry(qname.clone());
        if let Entry::Vacant(_) = entry {
            return ResolvePromise::Resolving;
        }
        entry.or_insert(LinkedList::new()).push_back(token);*/
        let mut was_none = false;
        {
            let mut res = self.resolving.get_mut(&(qname.clone(), qtype));
            //let mut res = res.as_mut();
            match res {
                Some(&mut (ref mut list, _)) => {
                    if !expect_response {
                        list.push_back(token);
                        println!("resolving1");
                        return ResolvePromise::Resolving;
                    }
                },
                None => {
                    was_none = true;
                }
            }
        }

        /*let preferred_cache = if self.ip_config.default_version == IP_V4 {
            self.cache4.as_mut().unwrap()
        } else {
            self.cache4.as_mut().unwrap()
        };
        let secondary_cache = if self.ip_config.default_version == IP_V6 {
            &self.cache6
        } else {
            &self.cache4
        };*/
        let mut nocache = false;
        {
            let (preferred_cache, _) = self.get_caches();
            let mut preferred_cache = preferred_cache.unwrap();

            //let mut preferred_cache = preferred_cache.unwrap();
            let records = preferred_cache.query(qname, true);
            match records {
                Some(option_list) => {
                    // in cache
                    match option_list {
                        &Some(ref ips) => {
                            return ResolvePromise::Resolved(token, Some(ips[0]));
                        },
                        &None => {
                            // negative cache entry (NXDOMAIN)
                            return ResolvePromise::Resolved(token, None);
                        }
                    }
                },
                None => {
                    // not in cache
                    nocache = true;
                }
            }
        }
        if was_none && nocache {
            let mut list = LinkedList::new();
            list.push_back(token);
            println!("ins res");
            self.resolving.insert((qname.clone(), qtype), (list, 0));
        }
        return ResolvePromise::Resolving;
    }

    pub fn from_config(ip_config: IpConfig, capacity: usize, cache_capacity: usize,
                       expiry_bucket_count: usize, expiry_bucket_secs: usize) -> Self {
        let mut result = CachingResolver::new(ip_config, capacity, cache_capacity,
                                              expiry_bucket_count, expiry_bucket_secs);
        result.parse_dns_config();
        result
    }

    fn parse_dns_config(&mut self) {
        let f = File::open("/etc/resolv.conf");
        if f.is_ok() {
            let f = f.unwrap();
            let file = BufReader::new(&f);
            for wrapped_line in file.lines() {
                let line = wrapped_line.unwrap();
                let words: Vec<&str> = line.split_whitespace().collect();
                if words.len() >= 2 && words[0] == "nameserver" {
                    let ip = IpAddr::from_str(words[1]);
                    if ip.is_ok() {
                        self.servers.push(SocketAddr::new(ip.unwrap(), 53));
                    }
                }
            }
        }
    }
}

pub struct Cache<TKey, TValue> {
    data: HashMap<Rc<TKey>, Option<VecDeque<TValue>>>,
    expiry: ExpiryHandler<ExpiryRef<TKey>>,
    value_capacity: usize
}


// TODO: Implement record expiry
impl<TKey: Eq + Hash, TValue> Cache<TKey, TValue> {
    pub fn new(capacity: usize, expiry_bucket_count: usize, expiry_bucket_secs: usize) -> Self {
        Cache {
            data: HashMap::with_capacity(capacity),
            expiry: ExpiryHandler::new(expiry_bucket_count, expiry_bucket_secs),
            value_capacity: 16
        }
    }

    pub fn clean(&mut self) {
        let ref mut dat = self.data;
        let mut fun = |e: &ExpiryRef<TKey> | {
            let mut cloned_ref = e.get_rc();
            let mut remove = false;
            {
                let rec = dat.get_mut(Rc::get_mut(&mut cloned_ref).unwrap());
                if rec.is_none() {
                    return;
                }
                let rec = rec.unwrap().as_mut();
                if rec.is_some() {
                    if e.is_negative() {
                        return;
                    }
                    let mut records = rec.unwrap();
                    records.remove(e.get_index());
                    if records.len() == 0 {
                        remove = true;
                    }
                } else {
                    if e.is_positive() {
                        return;
                    }
                    remove = true;
                }
            }
            if remove {
                dat.remove(Rc::get_mut(&mut cloned_ref).unwrap());
            }
        };
        self.expiry.clean(&mut fun);
    }

    pub fn insert_negative(&mut self, key: TKey, ttl: Duration) {
        self.expiry.add(ExpiryRef::Negative(Rc::new(key)), ttl);
    }

    pub fn insert(&mut self, key: TKey, value: TValue, ttl: Duration) {
        self.insert_with_direction(key, value, ttl, false);
    }

    pub fn insert_with_direction(&mut self, key: TKey, value: TValue, ttl: Duration, back: bool) {
        let expiry = SystemTime::now() + ttl;
        let keyref = Rc::new(key);
        let entry = self.data.entry(keyref.clone()).or_insert(Some(VecDeque::with_capacity(self.value_capacity)));
        let mut index = 0;
        match *entry {
            None => {
                let mut records = VecDeque::with_capacity(self.value_capacity);
                if back {
                    index = records.len();
                    records.push_back(value);
                } else {
                    records.push_front(value);
                }
                *entry = Some(records);
            },
            Some(ref mut records) => {
                if back {
                    records.push_back(value);
                    index = records.len();
                } else {
                    records.push_front(value);
                }
            }
        }
        self.expiry.add((ExpiryRef::Positive(keyref, index)), ttl);
    }

    pub fn query(&mut self, key: &TKey, rotate: bool) -> Option<&Option<VecDeque<TValue>>> {
        self.clean();
        if rotate {
            let result = self.data.get_mut(key);
            if result.is_some() {
                let mut record = result.unwrap();
                if let Some(ref mut records) = *record {
                    let element = records.pop_front().unwrap();
                    records.push_back(element);
                }
            }
        }
        self.data.get(key)
    }
}
