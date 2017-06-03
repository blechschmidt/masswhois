# MassWhois
Single-threaded epoll-based concurrent whois client in Rust.

## Usage
```
masswhois -c 10 -s 2001:503:ff39:1000::74 -o outfile.txt queries.txt
```
`-c` specifies the number of parallel connections to be opened at a time.

## State of development
Currently, MassWhois is very limited in its functionality. The whois servers still have to be specified using the `-s` command line argument.

### Todo
Support is highly wanted.
- Implement whois server referral support
- Implement automatic detection of whois servers
- Implement DNS pre-resolution of whois server names for better performance
- Implement query type detection
- Improve Rust-specific coding style (see TODOs)
- Implement timeouts
