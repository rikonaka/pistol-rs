# OS Detect Example

```rust
use pistol::{os_detect, Host, Target};
use std::time::Duration;
use std::net::Ipv4Addr;

fn main() {
    // The source and destination address is required.
    let src_ipv4 = Ipv4Addr::new(192, 168, 72, 128);
    // If the value of `source port` is `None`, the program will generate the source port randomly.
    let src_port = None;
    let dst_ipv4_1 = Ipv4Addr::new(192, 168, 72, 130);
    // `dst_open_tcp_port` must be a certain open tcp port.
    let dst_open_tcp_port_1 = 22;
    // `dst_closed_tcp_port` must be a certain closed tcp port.
    let dst_closed_tcp_port_1 = 8765;
    // `dst_closed_udp_port` must be a certain closed udp port.
    let dst_closed_udp_port_1 = 9876;
    let host1 = Host::new(
        dst_ipv4_1,
        Some(vec![
            dst_open_tcp_port_1,   // The order of these three ports cannot be disrupted.
            dst_closed_tcp_port_1,
            dst_closed_udp_port_1,
        ]),
    );
    let dst_ipv4_2 = Ipv4Addr::new(192, 168, 72, 136);
    let dst_open_tcp_port_2 = 22;
    let dst_closed_tcp_port_2 = 8765;
    let dst_closed_udp_port_2 = 9876;
    let host2 = Host::new(
        dst_ipv4_2,
        Some(vec![
            dst_open_tcp_port_2,
            dst_closed_tcp_port_2,
            dst_closed_udp_port_2,
        ]),
    );
    let target = Target::new(vec![host1, host2]);
    let max_loop = 8;
    // The timeout for the program to read the package.
    // It is recommended to set it to twice the RTT.
    let read_timeout = Duration::from_secs_f32(0.2);
    let nmap_os_db_file_path = "./nmap-os-db".to_string();
    let top_k = 3;
    let threads_num = 8;

    // The `fingerprint` is the obtained fingerprint of the target OS.
    // Return the `top_k` best results (the number of os detect result may not equal to `top_k`), sorted by score.
    let ret = os_detect(
        target,
        src_ipv4,
        src_port,
        nmap_os_db_file_path,
        top_k,
        threads_num,
        max_loop,
        read_timeout,
    )
    .unwrap();

    for (ip, (fingerprint, detect_ret)) in ret {
        println!(">>> IP:\n{}", ip);
        println!(">>> Pistol fingerprint:\n{}", fingerprint);
        println!(">>> Details:");
        for d in detect_ret {
            println!("{}", d);
        }
    }
}
```

## Output

* 192.168.72.130 - Ubuntu 22.04
* 192.168.72.129 - CentOS 7

### Ubuntu 22.04

```
>>> IP:
192.168.72.136
>>> Pistol fingerprint:
SCAN(V=PISTOL%D=12/14%OT=22%CT=8765%CU=9876PV=Y%DS=1%DC=D%G=Y%M=0C29%TM=657B21AA%P=RUST)
SEQ(SP=107%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%TG=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%TG=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%TG=40%CD=S)
>>> Details:
>>> Score: 83/101
>>> Info:
Linux 4.15.0-88-generic #88~16.04.1-Ubuntu SMP Wed Feb 12 04:19:15 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
Linux 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64 GNU/Linux
Linux 5.0.0-32-generic #34~18.04.2-Ubuntu SMP Thu Oct 10 10:36:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
Linux 5.2.10-yocto-standard #1 SMP PREEMPT Fri Oct 4 11:58:01 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
Linux 5.3.0-kali3-amd64
Linux 5.3.16-200.fc30.x86_64 #1 SMP Fri Dec 13 17:48:38 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
Linux 5.4.6-amd64.gbcm #3 SMP Thu Dec 26 13:55:41 -03 2019 x86_64 GNU/Linux
Linux 5.6.15-arch1-1 #1 SMP PREEMPT Wed, 27 May 2020 23:42:26 +0000 x86_64 GNU/Linux
Linux 5.2.11-arch1-1-ARCH
Linux 5.4.0-1012-raspi #12-Ubuntu SMP Wed May 27 04:08:35 UTC 2020 aarch64 aarch64 aarch64 GNU/Linux
>>> Fingerprint:
Linux 4.15 - 5.6
>>> Class:
Linux | Linux | 4.X | general purpose
Linux | Linux | 5.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:4 auto
cpe:/o:linux:linux_kernel:5 auto

>>> Score: 81/101
>>> Info:
Linux 5.0.0-23-generic #24-Ubuntu SMP Mon Jul 29 15:36:44 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
Linux 5.3.0-24-generic x86_64 Ubuntu 19.10
Linux 5.3.9-sunxi (root@builder) (gcc version 7.4.1 20181213 [linaro-7.4-2019.02
>>> Fingerprint:
Linux 5.0 - 5.3
>>> Class:
Linux | Linux | 5.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:5 auto

>>> Score: 80/101
>>> Info:
Linux 5.4.0-1008-raspi #8-Ubuntu SMP Wed Apr 8 11:13:06 UTC 2020 aarch64 aarch64 aarch64 GNU/Linux
>>> Fingerprint:
Linux 5.4
>>> Class:
Linux | Linux | 5.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:5.4 auto
```

### CentOS 7

```
>>> IP:
192.168.72.129
>>> Pistol fingerprint:
SCAN(V=PISTOL%D=12/14%OT=22%CT=54532%CU=34098PV=Y%DS=1%DC=D%G=Y%M=0C29%TM=657B21AA%P=RUST)
SEQ(SP=103%GCD=1%ISR=101%TI=Z%II=I%TS=A)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)
ECN(R=Y%DF=Y%TG=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=N)
T6(R=N)
T7(R=N)
U1(R=Y%DF=N%TG=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%TG=40%CD=S)
>>> Details:
>>> Score: 55/101
>>> Info:
Linux 3.10.0-327.13.1.el7.x86_64
Linux 3.12.5-200.fc19.i686 #1 SMP Tue Dec 17 22:46:33 UTC 2013 i686 i686 i386 GNU/Linux
Linux 3.13.5-200.fc20.x86_64 #1 SMP Mon Feb 24 16:51:35 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
Linux 3.11.0-17-generic #31-Ubuntu SMP Mon Feb 3 21:52:43 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
Linux 3.13.0-19-generic #40-Ubuntu SMP Mon Mar 24 02:36:06 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
Linux 3.14.3-1-ARCH #1 SMP PREEMPT Tue May 6 22:44:19 CEST 2014 x86_64 GNU/Linux
Linux 3.12.21-gentoo-r1 #1 SMP PREEMPT x86_64
Linux 3.12.28-1-ARCH #1 PREEMPT Tue Sep 9 12:57:11 MDT 2014 armv6l GNU/Linux
Linux 3.19.2-1-ARCH #1 SMP PREEMPT Wed Mar 18 16:36:01 CET 2015 i686 GNU/Linux
Linux 3.10.72 #10878 Thu Mar 19 04:41:15 CET 2015 mips GNU/Linux
Linux raspberrypi 4.1.7+ #817 PREEMPT Sat Sep 19 15:25:36 BST 2015 armv6l GNU/Linux
Linux 3.18.26 #8771 Fri Feb 5 03:08:28 CET 2016 mips
Linux 3.18.31 DD-WRT
Linux  4.2.0-27-generic #32~14.04.1-Ubuntu SMP Fri Jan 22 15:32:26 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
4.8.6-201.fc24.x86_64 #1 SMP Thu Nov 3 14:38:57 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
Linux 4.11.6-3-ARCH #1 SMP PREEMPT Thu Jun 22 12:21:46 CEST 2017 x86_64 GNU/Linux
>>> Fingerprint:
Linux 3.10 - 4.11
>>> Class:
Linux | Linux | 3.X | general purpose
Linux | Linux | 4.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:3 auto
cpe:/o:linux:linux_kernel:4 auto

>>> Score: 54/101
>>> Info:
Linux 3.10.0-514.26.2.el7.x86_64 #1 SMP Tue Jul 4 15:04:05 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux (CI=RI)
Linux 3.11.4-1-ARCH #1 SMP PREEMPT Sat Oct 5 21:22:51 CEST 2013 x86_64 GNU/Linux / Archlinux
Linux 3.11.0-12-generic #19-Ubuntu SMP Wed Oct 9 16:12:00 UTC 2013 i686 i686 i686 GNU/Linux
3.11.0-12-generic #19-Ubuntu SMP Wed Oct 9 16:20:46 UTC 2013 x86_64 x86_64 x86_64 GNU/Linux
Redhat Fedora 19 Linux kernel 3.11.6-200.fc19.x86_64
Linux 3.13.5-1-ARCH #1 SMP PREEMPT Sun Feb 23 00:25:24 CET 2014 x86_64 GNU/Linux
Linux 3.12.0-031200-generic #201311071835 SMP Thu Nov 7 23:36:07 UTC 2013 x86_64 x86_64 x86_64 GNU/Linux
Linux 3.12.3-1-ARCH #1 SMP PREEMPT Wed Dec 4 21:45:42 CET 2013 x86_64 GNU/Linux
Linux 3.12.6-1-ARCH #1 SMP PREEMPT Fri Dec 20 19:54:53 CET 2013 i686 GNU/Linux
Linux 3.12.6-1-ARCH #1 SMP PREEMPT Fri Jan 10 10:58:37 EST 2014 x86_64 GNU/Linux
Linux 3.11-1-amd64 #1 SMP Debian 3.11.6-1 (2013-10-27) x86_64 GNU/Linux
Linux 3.12.0-5.20131106git839f349.rpfr18.bcm2708/pidora
Linux 3.14.1-1-ARCH #1 SMP PREEMPT Mon Apr 14 20:40:47 CEST 2014 x86_64 GNU/Linux
Linux 3.12-kali1-686-pae #1 SMP Debian 3.12.6-2kali1 (2014-01-06) i686 GNU/Linux
Ubuntu 14.04 LTS (GNU/Linux 3.13.0-24-generic x86_64)
Ubuntu 14.04.2 LTS (GNU/Linux 3.19.1-x86_64 x86_64)
Linux 3.17.1-gentoo-r1 #1 SMP PREEMPT Mon Oct 20 17:04:15 PDT 2014 x86_64 Intel(R) Xeon(R) CPU E3-1245 v3 @ 3.40GHz GenuineIntel GNU/Linux
Linux 3.6.11+ #538 PREEMPT Fri Aug 30 20:42:08 BST 2013 armv6l GNU/Linux
Linux 3.17.4-1-ARCH #1 PREEMPT Fri Nov 21 22:27:00 MST 2014 armv5tel GNU/Linux
Linux 3.18.7+ #755 PREEMPT Thu Feb 12 17:14:31 GMT 2015 armv6l GNU/Linux
Linux 3.2.0-64-generic #97-Ubuntu SMP Wed Jun 4 22:04:21 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux (Ubuntu 12.04)
Linux 4.0.7-200.fc21.x86_64 #1 SMP Mon Jun 29 22:11:52 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
Linux 3.16.0-33-generic #44~14.04.1-Ubuntu
Linux 3.13.0-54-generic #91-Ubuntu SMP Tue May 26 19:15:08 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
Linux 4.1.7+ #817 PREEMPT Sat Sep 19 15:25:36 BST 2015 armv6l
Linux 4.2.0-2-ARCH #1 PREEMPT Mon Sep 7 03:47:39 MDT 2015 armv5tel GNU/Linux
Linux 4.4.0-12-generic #28-Ubuntu SMP Wed Mar 9 00:33:55 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
Linux 4.6.0-0.bpo.1-686-pae #1 SMP Debian 4.6.4-1~bpo8+1 (2016-08-11) i686 GNU/Linux
Linux 4.8.3-x86_64-linode76 #1 SMP
Linux 4.9
>>> Fingerprint:
Linux 3.2 - 4.9
>>> Class:
Linux | Linux | 3.X | general purpose
Linux | Linux | 4.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:3 auto
cpe:/o:linux:linux_kernel:4 auto

>>> Score: 54/101
>>> Info:
Linux 4.10.0-041000-lowlatency #201702191831 SMP PREEMPT Sun Feb 19 23:36:31 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
Linux 4.10.1-1-ARCH #1 SMP PREEMPT Sun Feb 26 21:08:53 UTC 2017 x86_64 GNU/Linux
Linux 4.10.12-sunxi #7 SMP Wed Apr 26 02:44:12 CEST 2017 armv7l GNU/Linux
>>> Fingerprint:
Linux 4.10
>>> Class:
Linux | Linux | 4.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:4.10 auto

>>> Score: 54/101
>>> Info:
Linux 4.4.5-1-ARCH #1 SMP PREEMPT Thu Mar 10 07:38:19 CET 2016 x86_64 GNU/Linux
>>> Fingerprint:
Linux 4.4
>>> Class:
Linux | Linux | 4.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:4.4 auto

>>> Score: 54/101
>>> Info:
Linux 5.1.9-arch1-1-ARCH #1 SMP PREEMPT Tue Jun 11 16:18:09 UTC 2019 x86_64 GNU/Linux
>>> Fingerprint:
Linux 5.1
>>> Class:
Linux | Linux | 5.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:5.1 auto

>>> Score: 53/101
>>> Info:
Linux 3.13.0-1-smp #2 SMP Fri Oct 17 14:29:25 BST 2014 x86_64 GNU/Linux
Linux 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt9-3~deb8u1 (2015-04-24) x86_64 GNU/Linux
Linux linux.netzwerk 3.16.6-2-desktop #1 SMP PREEMPT Mon Oct 20 13:47:22  UTC 2014 (feb42ea) i686 athlon i386 GNU/Linux openSUSE 13.2
>>> Fingerprint:
Linux 3.13 - 3.16
>>> Class:
Linux | Linux | 3.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:3 auto

>>> Score: 53/101
>>> Info:
Linux 3.16.0-4-686-pae #1 SMP Debian 3.16.7-ckt25-1 (2016-03-06) i686 GNU/Linux
>>> Fingerprint:
Linux 3.16
>>> Class:
Linux | Linux | 3.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:3.16 auto

>>> Score: 53/101
>>> Info:
Linux 3.18.13-2-ARCH #1 SMP PREEMPT Mon May 18 20:19:37 MDT 2015 armv7l GNU/Linux
Linux 3.19.0-26-generic #28-Ubuntu SMP Tue Aug 11 14:16:45 UTC 2015 i686 i686 i686 GNU/Linux
Linux 3.16.0-navtech-epu #4 SMP PREEMPT Wed Dec 2 13:16:34 GMT 2015 armv7l armv7l armv7l GNU/Linux
Linux 4.6.4-1-ARCH #1 SMP PREEMPT Mon Jul 11 19:12:32 CEST 2016 x86_64 GNU/Linux
>>> Fingerprint:
Linux 3.16 - 4.6
>>> Class:
Linux | Linux | 3.X | general purpose
Linux | Linux | 4.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:3 auto
cpe:/o:linux:linux_kernel:4 auto

>>> Score: 53/101
>>> Info:
OpenWRT CHAOS CALMER (Bleeding Edge, r45264) kernel 3.18.10-1-db18831523892bc50953de74ea42b8ac
Linksys wrt1900ac running OpenWrt Chaos Calmer r44455
Linux OpenWrt 3.18.8 #1 Thu Mar 12 19:12:22 UTC 2015 mips GNU/Linux
Linux OpenWrt 3.18.17 #1 Fri Jul 3 18:06:43 CEST 2015 mips GNU/Linux
Linux 3.18.20 #1 Fri Sep 4 21:55:57 CEST 2015 mips GNU/Linux
Linux 3.18.20 (buildbot@builder1) (gcc version 4.8.3 (OpenWrt/Linaro GCC 4.8-2014.04 r46450) ) #1 Fri Sep 4 21:55:57 CEST 2015
Linux 4.1.13 #1 Sun Dec 27 17:57:31 CET 2015 mips GNU/Linux
OpenWRT CHAOS CALMER (15.05.1, r48532)
OpenWrt Chaos Calmer 15.05.1 / LuCI 15.05-188-g87e9837 Release (git-16.018.33482-3201903), Linux 3.18.23
OpenWrt omnia 15.05 r47055 / LuCI 5ca9e5d2391f6ca149db4e53cda7c8f5d3ef6644 branch (git-16.335.29518-5ca9e5d), Linux 4.4.38
>>> Fingerprint:
OpenWrt Chaos Calmer 15.05 (Linux 3.18) or Designated Driver (Linux 4.1 or 4.4)
>>> Class:
Linux | Linux | 3.X | WAP
Linux | Linux | 4.X | WAP
>>> CPE:
cpe:/o:linux:linux_kernel:3.18
cpe:/o:linux:linux_kernel:4.1 auto

>>> Score: 53/101
>>> Info:
Linux 4.10
>>> Fingerprint:
Linux 4.10
>>> Class:
Linux | Linux | 4.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:4.10 auto

>>> Score: 53/101
>>> Info:
Linux 4.10.13-1-ARCH #1 SMP PREEMPT Thu Apr 27 12:15:09 CEST 2017 x86_64 GNU/Linux
>>> Fingerprint:
Linux 4.10
>>> Class:
Linux | Linux | 4.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:4.10 auto

>>> Score: 53/101
>>> Info:
Linux 4.4.13-v7+ #894 SMP Mon Jun 13 13:13:27 BST 2016 armv7l GNU/Linux
Linux 4.4.21-v7+ #911 SMP Thu Sep 15 14:22:38 BST 2016 armv7l GNU/Linux
>>> Fingerprint:
Linux 4.4
>>> Class:
Linux | Linux | 4.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:4.4 auto

>>> Score: 53/101
>>> Info:
Linux 4.4.13-v7+ #894 SMP Mon Jun 13 13:13:27 BST 2016 armv7l GNU/Linux
>>> Fingerprint:
Linux 4.4
>>> Class:
Linux | Linux | 4.X | general purpose
>>> CPE:
cpe:/o:linux:linux_kernel:4.4 auto

>>> Score: 53/101
>>> Info:
Linksys EA3500
>>> Fingerprint:
Linksys EA3500 WAP
>>> Class:
Linux | Linux || WAP
Linksys | embedded || WAP
>>> CPE:
cpe:/o:linux:linux_kernel auto
cpe:/h:linksys:ea3500 auto
```

