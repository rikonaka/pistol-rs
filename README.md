# pistol-rs

The library must be run as root (Linux) or administrator (Windows).

## Host discovery (Ping Scanning)

I implement `pistol` host discovery according to the nmap [documentation](https://nmap.org/book/host-discovery.html).

| Methods              | Detailed Documentation                                                                          | Notes                           |
| :------------------- | :---------------------------------------------------------------------------------------------- | :------------------------------ |
| [x] TCP SYN Ping     | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PS)       | IPv4 & IPv6 support             |
| [x] TCP ACK Ping     | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PA)       | IPv4 & IPv6 support             |
| [x] UDP Ping         | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PU)       | IPv4 & IPv6 support             |
| [x] ICMP Ping        | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-icmpping) | IPv4 & IPv6 support (ICMPv6)    |
| [x] ARP Scan         | [nmap references](https://nmap.org/book/host-discovery-techniques.html#arp-scan)                | IPv4 support                    |
| [ ] IP Protocol Ping | [nmap references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PO)       | Complicated and not very useful |

## Port Scanning Techniques and Algorithms

I implement `pistol` transport layer scan according to the nmap [pdf](https://nmap.org/nmap_doc.html) and [documentation](https://nmap.org/book/scan-methods.html).

| Methods                 | Detailed Documentation                                                        | Notes                                   |
| :---------------------- | :---------------------------------------------------------------------------- | :-------------------------------------- |
| [x] TCP SYN Scan        | [nmap references](https://nmap.org/book/synscan.html)                         | IPv4 & IPv6 support                     |
| [x] TCP Connect() Scan  | [nmap references](https://nmap.org/book/scan-methods-connect-scan.html)       | IPv4 & IPv6 support                     |
| [x] TCP FIN Scan        | [nmap references](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) | IPv4 & IPv6 support                     |
| [x] TCP Null Scan       | [nmap references](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) | IPv4 & IPv6 support                     |
| [x] TCP Xmas Scan       | [nmap references](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) | IPv4 & IPv6 support                     |
| [x] TCP ACK Scan        | [nmap references](https://nmap.org/book/scan-methods-ack-scan.html)           | IPv4 & IPv6 support                     |
| [x] TCP Window Scan     | [nmap references](https://nmap.org/book/scan-methods-window-scan.html)        | IPv4 & IPv6 support                     |
| [x] TCP Maimon Scan     | [nmap references](https://nmap.org/book/scan-methods-maimon-scan.html)        | IPv4 & IPv6 support                     |
| [x] UDP Scan            | [nmap references](https://nmap.org/book/scan-methods-udp-scan.html)           | IPv4 & IPv6 support                     |
| [x] TCP Idle Scan       | [nmap references](https://nmap.org/book/idlescan.html)                        | IPv4 support                            |
| [x] IP Protocol Scan    | [nmap references](https://nmap.org/book/scan-methods-ip-protocol-scan.html)   | IPv4 support                            |
| [ ] TCP FTP Bounce Scan | [nmap references](https://nmap.org/book/scan-methods-ftp-bounce-scan.html)    | The bugs exploited have long been fixed |


## Flood attack

| Methods           | Notes                        |
| :---------------- | :--------------------------- |
| [x] TCP SYN Flood | IPv4 & IPv6 support          |
| [x] TCP ACK Flood | IPv4 & IPv6 support          |
| [x] UDP Flood     | IPv4 & IPv6 support          |
| [x] ICMP Flood    | IPv4 & IPv6 support (ICMPv6) |

## Operating system detect

Under implementation.

Supports the detecting and analysis of nmap operating system fingerprint database format, perfectly compatible with nmap operating system detection algorithms.

## CLI program

I also implement a demo [code](https://github.com/rikonaka/pistol_cli-rs) here.