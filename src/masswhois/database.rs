use std::net::IpAddr;
use std::collections::HashMap;
use std::str::FromStr;
use masswhois::*;
use masswhois::query::*;

pub static SERVER_ARIN: &'static str = "whois.arin.net";
pub static SERVER_IANA: &'static str = "whois.iana.org";
pub static SERVER_VERISIGN: &'static str = "whois.verisign-grs.com";

static MAP_DOMAIN_SERVER: &'static str = include_str!("../../data/domain_servers.txt");
static MAP_SERVER_IP: &'static str = include_str!("../../data/server_ip.txt");

pub struct WhoisDatabase {
    pub map_domain_servers: HashMap<String, String>, // map domain to whois server
    pub map_server_ips: HashMap<String, Vec<IpAddr>>, // map whois server name to addresses
}

impl WhoisDatabase {
    pub fn new(ip_config: &IpConfig) -> WhoisDatabase {
        let mut result = WhoisDatabase {
            map_domain_servers: Default::default(),
            map_server_ips: Default::default(),
        };
        result.read_domain_servers();
        result.read_server_ips(ip_config);
        result
    }

    fn read_domain_servers(&mut self) {
        for l in MAP_DOMAIN_SERVER.lines() {
            let trimmed: String = String::from(l);
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
            let trimmed: String = String::from(l);
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

    pub fn get_server<'a>(&'a self, query: &'a WhoisQuery) -> Option<&'a str> {
        match *query {
            WhoisQuery::Domain(ref x) => {
                let mut is_tld = true;
                for (pos, ch) in x.char_indices() {
                    if ch == '.' {
                        is_tld = false;
                        let part = &x.as_str()[pos + 1..];
                        let result = self.map_domain_servers.get(&String::from(part));
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

    pub fn get_server_ip<'a>(&'a self, try: usize, server: Option<&'a str>) -> Option<IpAddr> {
        if server.is_none() {
            None
        } else{
            let server_str = String::from(server.unwrap());
            let ips = self.map_server_ips.get(&server_str);
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
