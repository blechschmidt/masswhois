#!/bin/bash

while read -r line; do
    if echo "$line" | grep -v -qE '^\s*#'; then
	tld_info=$(whois -h whois.iana.org "$line")
	whois_server=$(echo "$tld_info" | pcregrep -o1 "\s*whois:\s+(.+)")
	echo "$line" "$whois_server" "$dns_a" "$dns_aaaa"
    fi
done <tlds.txt>domain_servers.txt
