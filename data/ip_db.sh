#!/bin/sh

function _get_ips {
    name="$1"
    dns_a=$(dig +short -t A  "$name")
    dns_aaaa=$(dig +short -t AAAA "$name")
    while read -r line; do
	if echo "$line" | grep -qE '\.$'; then
	    get_ips "$line"
	else
	    echo "$line"
	fi
    done <<< "$dns_a"
    while read -r line; do
	if echo "$line" | grep -qE '\.$'; then
	    get_ips "$line"
	else
	    echo "$line"
	fi
    done <<< "$dns_aaaa"
}

function get_ips {
    _get_ips "$1" | sort | uniq
}

function create_db {
    servers=$(cat domain_servers.txt | awk '{print $2}')
    while read -r line; do
        if [[ ! -z "$line" ]]; then
            ips=$(get_ips "$line" | xargs)
            echo "$line" "$ips"
        fi
    done <<< "$servers"
}

create_db | sort | uniq > server_ip.txt
