# MassWhois
Single-threaded epoll-based concurrent bulk whois client in Rust.

## Usage
```
Usage: masswhois [OPTIONS] [OBJECT]...

-c N       Number of concurrent lookups
-s IP      Server IP address to use in case inference fails
           Can be specified multiple times
-o FILE    File where binary output is written to
-i FILE    Query objects from file instead of using command line arguments
--ip 4,6   IP version support. Preferred version first

--no-infer-types      Do not infer the query type
--no-infer-servers    Do not infer the query server
--check-availability  Perform a domain availability check only.
```

## Building
MassWhois relies on [Cargo](https://crates.io/), the Rust package manager.
It can be installed using `apt-get install cargo` on Debian-based systems.

Run `cargo build --release` within the cloned folder. The resulting `masswhois` binary will be stored in `target/release/`.

## State of development
Currently, MassWhois is in an early stage of development and the only supported objects are domains and AS numbers.

### Todo
Support is highly wanted.
- Improve Rust-specific coding style (see TODOs)
- Implement timeouts
- Implement display/statistics
- Handle timeouts/network connectivity issues gracefully instead of panicking
- Automatic IP version support detection
- Testing
