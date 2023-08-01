# pistol-rs

## Support scan methods

I implement `pistol` transport layer scan according to the nmap [documentation](https://nmap.org/nmap_doc.html).

| Methods            | Detailed Documentation                                                        |
| :----------------- | :---------------------------------------------------------------------------- |
| ARP Scan           | [wiki references](https://en.wikipedia.org/wiki/Address_Resolution_Protocol)  |
| TCP SYN Scan       | [nmap references](https://nmap.org/book/synscan.html)                         |
| TCP Connect() Scan | [nmap references](https://nmap.org/book/scan-methods-connect-scan.html)       |
| TCP FIN Scan       | [nmap references](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) |
| TCP Null Scan      | [nmap references](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) |
| TCP Xmas Scan      | [nmap references](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html) |
| TCP ACK Scan       | [nmap references](https://nmap.org/book/scan-methods-ack-scan.html)           |
| TCP Window Scan    | [nmap references](https://nmap.org/book/scan-methods-window-scan.html)        |
| TCP Maimon Scan    | [nmap references](https://nmap.org/book/scan-methods-maimon-scan.html)        |
| TCP Idle Scan      | [nmap references](https://nmap.org/book/idlescan.html)                        |
| UDP Scan           | [nmap references](https://nmap.org/book/scan-methods-udp-scan.html)           |