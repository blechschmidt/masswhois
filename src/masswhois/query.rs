use std::net::IpAddr;
use std::str::FromStr;

#[derive(Clone)]
pub enum WhoisQuery {
    Domain(String),
    IpAddr(IpAddr),
    AS(u32),
    Unspecified(String)
}

impl WhoisQuery {
    pub fn new(query: String, unspecified: bool) -> Self {
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
