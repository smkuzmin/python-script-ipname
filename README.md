```
IPName v1.5 - IPv4 Resolver

Reads IPv4 addresses, networks and hostnames from STDIN, resolves them
to 'ip # name' format via DNS and WHOIS lookups, and outputs the list to STDOUT in order of appearance.

FEATURES:
  - Comments (lines starting with #) are passed through unchanged
  - Invalid lines are printed as-is
  - Pure Python WHOIS client (no external whois command required)
  - Uses DNS and WHOIS for resolution only if no comment present (may be slow)
  - Normalizes subnet masks to CIDR prefix (e.g., /255.255.255.0 → /24)
  - Single IP addresses output without /32 prefix

INPUT FORMAT:
  77.88.55.88               # Single IP address
  77.88.55.0/24             # Network with CIDR prefix
  77.88.55.0/255.255.255.0  # Network with subnet mask
  yandex.ru                 # Hostname

OUTPUT FORMAT:
  77.88.55.88        # yandex.ru
  77.88.55.0/24      # YANDEX-77-88-55-0
  77.88.55.0/24      # YANDEX-77-88-55-0
  5.255.255.77       # yandex.ru
  77.88.44.55        # yandex.ru
  77.88.55.88        # yandex.ru

USAGE:
  cat input_file | ipname
  ipname < file.lst
  ipname < file.lst > output.lst
```
