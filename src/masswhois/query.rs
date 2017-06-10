use std::net::IpAddr;
use std::str::FromStr;
use masswhois::database::*;

pub enum WhoisQuery {
    Domain(String),
    IpAddr(IpAddr),
    AS(u32),
    Unspecified(String)
}

impl WhoisQuery {
    pub fn new(query: String, unspecified: bool) -> WhoisQuery {
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
    pub fn construct_query(&self, server: &str) -> String {
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
