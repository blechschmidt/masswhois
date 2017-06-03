#!/bin/sh

(echo "# Source: http://data.iana.org/TLD/tlds-alpha-by-domain.txt"; wget -O- http://data.iana.org/TLD/tlds-alpha-by-domain.txt) > tlds.txt
