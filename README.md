# pistol-rs

## Host discovery (Ping Scanning)

I implement `pistol` host discovery according to the nmap [documentation](https://nmap.org/book/host-discovery.html).

| Methods              | Detailed Documentation                                                                          | Notes   |
| :------------------- | :---------------------------------------------------------------------------------------------- | :------ |
| [x] TCP SYN Ping     | [namp references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PS)       |         |
| [x] TCP ACK Ping     | [namp references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PA)       |         |
| [x] UDP Ping         | [namp references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PU)       |         |
| [x] ICMP Ping        | [namp references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-icmpping) |         |
| [x] ARP Scan         | [namp references](https://nmap.org/book/host-discovery-techniques.html#arp-scan)                |         |
| [ ] IP Protocol Ping | [namp references](https://nmap.org/book/host-discovery-techniques.html#host-discovery-PO)       | Useless |

## Port Scanning Techniques and Algorithms

I implement `pistol` transport layer scan according to the nmap [pdf](https://nmap.org/nmap_doc.html) and [documentation](https://nmap.org/book/scan-methods.html).

| Methods                 | Detailed Documentation                                                        | Notes                                   |
| :---------------------- | :---------------------------------------------------------------------------- | :-------------------------------------- |
| [x] TCP SYN Scan        | [nmap references](https://nmap.org/book/synscan.html)                         |                                         |
| [x] TCP Connect() Scan  | [nmap references](https://nmap.org/book/scan-methods-connect-scan.html)       |                                         |
| [x] TCP FIN Scan        | [nmap references](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) |                                         |
| [x] TCP Null Scan       | [nmap references](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) |                                         |
| [x] TCP Xmas Scan       | [nmap references](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) |                                         |
| [x] TCP ACK Scan        | [nmap references](https://nmap.org/book/scan-methods-ack-scan.html)           |                                         |
| [x] TCP Window Scan     | [nmap references](https://nmap.org/book/scan-methods-window-scan.html)        |                                         |
| [x] TCP Maimon Scan     | [nmap references](https://nmap.org/book/scan-methods-maimon-scan.html)        |                                         |
| [x] TCP Idle Scan       | [nmap references](https://nmap.org/book/idlescan.html)                        |                                         |
| [x] IP Protocol Scan    | [nmap references](https://nmap.org/book/scan-methods-ip-protocol-scan.html)   |                                         |
| [x] UDP Scan            | [nmap references](https://nmap.org/book/scan-methods-udp-scan.html)           |                                         |
| [ ] TCP FTP Bounce Scan | [nmap references](https://nmap.org/book/scan-methods-ftp-bounce-scan.html)    | The bugs exploited have long been fixed |

