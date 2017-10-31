use std::net::IpAddr;
use std::collections::HashMap;
use std::str;
use std::ops::Range;
use std::str::FromStr;
use masswhois::*;
use masswhois::query::*;
use masswhois::client::{WhoisClient, Availability};
extern crate regex;
use self::regex::bytes::Regex;

pub static SERVER_ARIN: &'static str = "whois.arin.net";
pub static SERVER_IANA: &'static str = "whois.iana.org";
pub static SERVER_VERISIGN: &'static str = "whois.verisign-grs.com";

static MAP_DOMAIN_SERVER: &'static str = include_str!("../../data/domain_servers.txt");
static MAP_SERVER_IP: &'static str = include_str!("../../data/server_ip.txt");
static MAP_SERVER_QUERY: &'static str = include_str!("../../data/server_query.txt");
static MAP_SERVER_REFERRAL: &'static str = include_str!("../../data/server_referral.txt");
static MAP_SERVER_AVAILABILITY: &'static str = include_str!("../../data/domain_availability.txt");
static MAP_ASN_SERVER: &'static str = include_str!("../../data/asn_server.txt");

pub struct WhoisDatabase {
    pub map_domain_servers: HashMap<String, String>, // map domain to whois server
    pub map_server_ips: HashMap<String, Vec<IpAddr>>, // map whois server name to addresses
    pub map_server_query: HashMap<(WhoisQueryType, String), (String, String)>,
    pub map_server_referral: HashMap<String, Regex>,
    pub general_availability: LinkedList<Regex>,
    pub asn_map: AsnMap
}

pub struct AsnMap {
    table: Vec<(Range<usize>, String)>
}

impl AsnMap {
    pub fn load() -> Self {
        let mut map = AsnMap {
            table: Default::default()
        };

        for l in MAP_ASN_SERVER.lines() {
            let trimmed: String = String::from(l.trim());
            if trimmed == String::from("") || trimmed.starts_with("#") {
                continue;
            }
            let mut split = trimmed.split_whitespace();
            let lower = split.next().unwrap().parse::<usize>().unwrap();
            let upper = split.next().unwrap().parse::<usize>().unwrap();
            let server = String::from(split.next().unwrap());
            map.table.push((Range{start: lower, end: upper}, server));
        }

        map
    }

    pub fn find(&self, asn: usize) -> String {
        let mut search = Range {
            start: 0,
            end: self.table.len()
        };
        loop {
            let index = (search.start + search.end) / 2;
            let result = self.table.get(index);
            if result.is_none() || search.start > search.end {
                return String::from(SERVER_ARIN);
            }
            let tuple = result.unwrap();
            if asn < tuple.0.start {
                if index == 0 {
                    return String::from(SERVER_ARIN);
                }

                search.end = index - 1;
            }
            else if asn > tuple.0.end {
                search.start = index + 1;
            }
            else {
                return tuple.1.clone();
            }
        }
    }
}

impl WhoisDatabase {
    pub fn new(ip_config: &IpConfig) -> WhoisDatabase {
        let mut result = WhoisDatabase {
            map_domain_servers: Default::default(),
            map_server_ips: Default::default(),
            map_server_query: Default::default(),
            map_server_referral: Default::default(),
            general_availability: Default::default(),
            asn_map: AsnMap::load()
        };
        result.read_domain_servers();
        result.read_server_ips(ip_config);
        result.read_server_queries();
        result.read_server_referrals();
        result.read_server_availability();
        result
    }

    pub fn get_referral_server(&mut self, client: &WhoisClient) -> Option<String> {
        match client.server {
            Some(ref s) => {
                let result = self.map_server_referral.get(s);
                match result {
                    Some(regex) => {
                        let data = client.inbuf.as_ref();
                        let search = regex.captures(data);
                        match search {
                            Some(m) => {
                                let capture = m.get(1);
                                match capture {
                                    Some(c) => {
                                        let bytes = c.as_bytes().to_vec();
                                        let referral_server = String::from_utf8(bytes);
                                        match referral_server {
                                            Ok(s) => Some(s),
                                            _ => None
                                        }
                                    },
                                    _ => None
                                }
                            },
                            _ => None
                        }
                    },
                    _ => None
                }
            }
            _ => None
        }
    }

    fn read_server_referrals(&mut self) {
        for l in MAP_SERVER_REFERRAL.lines() {
            let trimmed: String = String::from(l.trim());
            if trimmed == String::from("") || trimmed.starts_with("#") {
                continue;
            }
            let space_pos = trimmed.find(' ').unwrap();
            let server: String = l.chars().take(space_pos).collect();
            let rest: String = l.chars().skip(space_pos + 1).take(trimmed.len() - (space_pos + 1)).collect();
            let expr = Regex::new(rest.as_str()).expect("Invalid regular expression.");
            self.map_server_referral.insert(server, expr);
        }
    }

    fn read_server_availability(&mut self) {
        for l in MAP_SERVER_AVAILABILITY.lines() {
            let trimmed: String = String::from(l.trim());
            if trimmed == String::from("") || trimmed.starts_with("#") {
                continue;
            }
            let expr = Regex::new(trimmed.as_str()).expect("Invalid regular expression.");
            self.general_availability.push_back(expr);
        }
    }

    pub fn availability(&self, client: &WhoisClient) -> Availability {
        let data = client.inbuf.as_ref();
        for r in self.general_availability.iter() {
            if r.is_match(data) {
                return Availability::AVAILABLE;
            }
        }
        Availability::UNAVAILABLE
    }

    fn read_server_queries(&mut self) {
        for l in MAP_SERVER_QUERY.lines() {
            let trimmed: String = String::from(l.trim());
            if trimmed == String::from("") || trimmed.starts_with("#") {
                continue;
            }
            let space_pos = trimmed.find(' ').unwrap();
            let server: String = l.chars().take(space_pos).collect();
            let rest: String = l.chars().skip(space_pos + 1).take(trimmed.len() - (space_pos + 1)).collect();
            let domain_pos = rest.find("$domain");
            let asn_pos = rest.find("$asn");
            let (qtype, len, pos) = if domain_pos.is_some() {
                (WhoisQueryType::Domain, 7, domain_pos.unwrap())
            } else {
                (WhoisQueryType::AS, 4, asn_pos.expect("Invalid line within server query file"))
            };
            let prefix: String = rest.chars().take(pos).collect();
            let suffix: String = rest.chars().skip(pos + len).take(rest.len() - pos - len).collect();
            self.map_server_query.insert((qtype, server), (prefix, suffix));
        }
    }

    fn read_domain_servers(&mut self) {
        for l in MAP_DOMAIN_SERVER.lines() {
            let trimmed: String = String::from(l.trim());
            if trimmed == String::from("") || trimmed.starts_with("#") {
                continue;
            }
            let mut fields = trimmed.split_whitespace();
            let domain = String::from(fields.next().unwrap()).to_lowercase();
            let server = fields.next().map(|x| String::from(x).to_lowercase());
            if server.is_some() {
                self.map_domain_servers.insert(domain, server.unwrap());
            }
        }
    }

    fn read_server_ips(&mut self, ip_config: &IpConfig) {
        for l in MAP_SERVER_IP.lines() {
            let trimmed: String = String::from(l.trim());
            if trimmed == String::from("") || trimmed.starts_with("#") {
                continue;
            }
            let mut fields = trimmed.split_whitespace();
            let server = String::from(fields.next().unwrap()).to_lowercase();
            let mut ip4_addrs: Vec<IpAddr> = Default::default();
            let mut ip6_addrs: Vec<IpAddr> = Default::default();
            let mut ip_addrs: Vec<IpAddr> = Default::default();
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
            self.map_server_ips.insert(server, ip_addrs);
        }
    }

    pub fn get_server(&self, query: &WhoisQuery) -> (Option<String>, String) {
        match *query {
            WhoisQuery::Domain(ref x) => {
                let mut is_tld = true;
                for (pos, ch) in x.char_indices() {
                    if ch == '.' {
                        is_tld = false;
                        let part = &x.as_str()[pos + 1..];
                        let name = String::from(part);
                        let result = self.map_domain_servers.get(&name);
                        if result.is_some() {
                            let server_name = result.unwrap();
                            let q = (query.get_type(), server_name.clone());
                            let server_query = self.map_server_query.get(&q);
                            if server_query.is_some() {
                                let &(ref prefix, ref suffix) = server_query.unwrap();
                                let mut query_string = prefix.clone();
                                query_string += &query.to_string();
                                query_string += &suffix;
                                return (Some(server_name.clone()), query_string);
                            }
                            else {
                                return (Some(server_name.clone()), query.to_string() + "\n");
                            }
                        }
                    }
                }
                if is_tld {
                    return (Some(String::from(SERVER_IANA)), query.to_string() + "\n");
                }
                (None, query.to_string() + "\n")
            },
            WhoisQuery::AS(x) => {

                let server_name = self.asn_map.find(x as usize);

                let q = (query.get_type(), server_name.clone());
                let server_query = self.map_server_query.get(&q);
                if server_query.is_some() {
                    let &(ref prefix, ref suffix) = server_query.unwrap();
                    let mut query_string = prefix.clone();
                    query_string += &query.to_string();
                    query_string += &suffix;
                    return (Some(server_name.clone()), query_string);
                }
                else {
                    return (Some(server_name.clone()), query.to_string() + "\n");
                }
            },
            // TODO: Implement other types
            _ => (None, query.to_string() + "\n")
        }
    }

    pub fn get_server_ip(&self, try: usize, server: Option<&String>) -> Option<IpAddr> {
        if server.is_none() {
            None
        } else{
            let server_str = server.unwrap();
            let ips = self.map_server_ips.get(server_str);
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
