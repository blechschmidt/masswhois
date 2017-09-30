extern crate mio;
extern crate netbuf;
extern crate byteorder;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate indoc;

pub mod masswhois;
pub mod dnsutils;

use std::env;
use std::str::FromStr;
use std::net::IpAddr;
use std::io;
use std::io::{BufReader, BufRead, Write, BufWriter};
use std::fs::File;
use masswhois::*;
use masswhois::query::*;
use masswhois::handler::*;
use std::process::exit;

fn main() {
    let mut args = env::args();
    let program = args.next();
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut servers: Vec<IpAddr> = Default::default();
    let mut concurrency: usize = 5;
    let mut ip_config = IpConfig {
        supported_versions: IP_V4,
        default_version: IP_V4
    };
    let mut infer_types = true;
    let mut infer_servers = true;
    let mut stdout = false;
    let mut queries : Option<String> = None;

    loop {
        match args.next() {
            Some(x) => match x.as_ref() {
                "-h" | "--help" => {
                    let help = indoc!("\
                    Usage: masswhois [OPTIONS] [OBJECT]...

                    -c N       Number of concurrent lookups
                    -s IP      Server IP address to use in case inference fails
                               Can be specified multiple times
                    -o FILE    File where binary output is written to
                    -i FILE    Query objects from file instead of using command line arguments
                    --ip 4,6   IP version support. Preferred version first

                    --no-infer-types     Do not infer the query type
                    --no-infer-servers   Do not infer the query server");
                    println!("{}", help);
                    exit(0);
                },
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
                "-i" | "--infile" => {
                    if infile.is_some() {
                        panic!("Invalid parameter.");
                    }
                    Some(args.next().expect("Missing infile."));
                },
                x => {
                    if queries.is_none() {
                        queries = Some(String::from_str(x).expect("String conversion failure."));
                    }
                    else {
                        queries.as_mut().unwrap().push_str("\n");
                        queries.as_mut().unwrap().push_str(x);
                    }
                }
            },
            None => {
                break;
            }
        }
    }
    let mut reader: Box<BufRead> = if infile == None || infile == Some(String::from("-")) {
        Box::new(BufReader::new(io::stdin()))
    } else {
        Box::new(BufReader::new(File::open(infile.unwrap()).expect("Error opening file.")))
    };
    let writer: Box<Write> = if outfile == None || outfile == Some(String::from("-")) {
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

    let r: Box<WhoisRawQuerySupplier> = match queries {
        None => Box::new(WhoisRawQueryReader::new(reader)),
        Some(q) => Box::new(WhoisRawQueryCmd::new(q))
    };

    let mut masswhois: MassWhois = MassWhois::new(concurrency, ip_config, infer_servers, r, binary_output, infer_types);
    masswhois.start();
}
