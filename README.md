```
IPName v1.9 - IPv4 Resolver

Reads IPv4 addresses, networks and hostnames from STDIN, resolves them
to 'ip # name' format via DNS and WHOIS lookups, and outputs the list to STDOUT in order of appearance.

FEATURES:
  - Comments (lines starting with #) are passed through unchanged
  - Unresolved entries are hidden when using the --resolved-only flag
  - Pure Python WHOIS client (no external whois command required)
  - DNS and WHOIS resolution is performed only when no explicit comment is provided
  - Normalizes subnet masks to CIDR notation (e.g., /255.255.255.0 -> /24)
  - Single IP addresses are output without the /32 suffix

INPUT FORMAT:
  77.88.55.88                 Single IP address
  77.88.55.0/24               Network with CIDR prefix
  77.88.55.0/255.255.255.0    Network with subnet mask
  yandex.ru                   Hostname

OUTPUT FORMAT:
  77.88.55.88        # yandex.ru
  77.88.55.0/24      # YANDEX-77-88-55-0
  77.88.55.0/24      # YANDEX-77-88-55-0
  5.255.255.77       # yandex.ru
  77.88.44.55        # yandex.ru
  77.88.55.88        # yandex.ru

USAGE:
  cat infile.lst | ipname [OPTIONS]
  ipname [OPTIONS] < infile.lst > outfile.lst

OPTIONS:
  -r, --resolved-only        Output only successfully resolved entries
  -w, --resolved-wan-only    Output only public (WAN) resolved entries
  -l, --resolved-lan-only    Output only private (LAN) resolved entries
```
