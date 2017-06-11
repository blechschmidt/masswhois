# MassWhois
Single-threaded epoll-based concurrent whois client in Rust.

## Usage
```
masswhois -c 10 queries.txt
```
`-c` specifies the number of parallel connections to be opened at a time. `queries.txt` contains a list of domains to query for.

## State of development
Currently, MassWhois is very limited in its functionality. IP addresses of whois servers are still hardcoded only as DNS resolution is not yet implemented as it may not be blocking. Most servers for domain whois are recognized automatically already and the `-s` argument is no longer required, but referrals (such as for .com domains) are not supported yet.

### Todo
Support is highly wanted.
- Implement whois server referral support
- Implement DNS name resolution of whois servers
- Implement query type detection
- Improve Rust-specific coding style (see TODOs)
- Implement timeouts
- Implement display/statistics
- Handle timeouts/network connectivity issues gracefully instead of panicking
- Testing
