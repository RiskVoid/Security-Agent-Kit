#!/bin/sh
# Build the tinyproxy filter from allowlist.txt plus EGRESS_EXTRA_DOMAINS (comma or space separated, from .env).
# Each entry allows the domain and its subdomains.
set -eu
{
  grep -v '^[[:space:]]*#' /etc/rvkit/allowlist.txt
  echo "${EGRESS_EXTRA_DOMAINS:-}" | tr ', ' '\n\n'
} | sed 's/[[:space:]]//g; s/^\*\.//; s/\.$//' | grep -E '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' | sort -u |
  sed 's/\./\\./g; s/^/(^|\\.)/; s/$/$/' > /etc/tinyproxy/filter
echo "egress proxy: $(wc -l < /etc/tinyproxy/filter) allowed domains (and their subdomains)"
exec tinyproxy -d -c /etc/tinyproxy/tinyproxy.conf
