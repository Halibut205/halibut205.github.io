---
title: "SOC HTB - Section 9: Working with IDS/IPS"
date: 2026-06-24 00:00:00 +0700
categories: [HTB SOC Jobpath]
tags: [cdsa, study-notes, htb-soc-jobpath, ids, ips, snort, suricata]
---

# Working with IDS/IPS

# **Introduction To IDS/IPS**

**Intrusion Detection Systems (IDS)** and **Intrusion Prevention Systems (IPS)** are critical components of a defense-in-depth network security strategy. While both utilize similar detection methods, their primary functions and network placements differ based on how they handle potential threats.

| **Feature** | **Intrusion Detection System (IDS)** | **Intrusion Prevention System (IPS)** |
| --- | --- | --- |
| **Function** | Passively monitors traffic and sends alerts to a management station. | Actively intervenes and prevents detected threats. |
| **Action** | Does *not* stop or block intrusions. | Drops malicious packets, blocks traffic, and resets connections. |
| **Placement** | Behind the firewall (internal side) to monitor traffic that bypassed the perimeter. | Inline, directly behind the firewall, where it has the authority to block traffic. |

Both systems use two primary methods to balance threat detection and minimize false alarms:

- Identifies known threats **using previously established bad patterns** and **malware signatures**.
- Establishes a **baseline** of "normal" network behavior and **triggers actions for any deviations**. This is proactive against new threats but is more prone to false positives.

Deployment:

- **Network-based:** Typically placed behind the firewall to focus on internal traffic and threats that have made it past the first line of defense.
- **Host-based (HIDS/HIPS):** Can be implemented directly on individual host machines to monitor their specific inbound and outbound traffic.

Updates:

To maintain a strong defense, the systems require ongoing management and integration into broader security monitoring frameworks.

Because the threat landscape is constantly changing, security teams must proactively maintain these systems by:

- Regularly updating threat signatures to catch newly discovered malware.
- Continuously fine-tuning anomaly detection algorithms to ensure accuracy and reduce false positives.

**SIEM** systems act as the central hub for network security:

- **Log Aggregation:** They collect logs from IDS, IPS, and various other network devices.
- **Event Correlation:** By analyzing data from multiple sources, SIEMs can connect the dots between seemingly unrelated events to detect complex, coordinated attacks.
- **Unified Visibility:** This centralized approach gives security teams a complete picture of the network, enabling faster and more effective incident response.

# Suricata

## Suricata Fundamentals

**Suricata** is a highly efficient, open-source network security tool utilized for Intrusion Detection (IDS), Intrusion Prevention (IPS), and Network Security Monitoring (NSM).

- It is a community-led project managed by the non-profit *Open Information Security Foundation (OISF)*.
- It thoroughly inspects all network traffic, including deep dives into *individual application-layer transactions*, to detect malicious activity.
- Its effectiveness relies on a *sophisticated set of rules* that guild its analysis and identify potential threats.
- It is *exceptionally fast and optimized* to run at high speeds on both standard, off-the-shelf hardware and specialized equipment.

### **Suricata Operation Modes**

Suricata operates in four (4) distinct modes:

| **Mode** | **Role / Stance** | **Action Taken** | **Key Advantages** | **Drawbacks** |
| --- | --- | --- | --- | --- |
| **Intrusion Detection System (IDS)** | Silent Observer | Passively examines traffic and flags potential attacks without intervening. | Augments network visibility and accelerates response times. | Offers no direct protection or active blocking. |
| **Intrusion Prevention System (IPS)** | Proactive / Inline | Scrutinizes all traffic and blocks attacks before they reach the internal network. | Proactively thwarts threats. | May introduce network latency; risks blocking legitimate traffic if rules aren't rigorously tested. |
| **Intrusion Detection Prevention System (IDPS)** | Hybrid | Passively monitors traffic but actively transmits RST (reset) packets against abnormal activities. | Strikes a balance between active protection and maintaining low latency. | Requires careful tuning to ensure RST packets effectively disrupt the correct sessions. |
| **Network Security Monitoring (NSM)** | Dedicated Logger | Logs all encountered network information without performing active/passive analysis or prevention. | Provides a wealth of historical data for retrospective incident investigations. | Generates a very high volume of data to store and manage. |

### **Suricata Inputs**

Inputs dictate how Suricata ingests network traffic for inspection. They are divided into two main categories: *Offline* and *Live*.

| **Category** | **Interface / Method** | **Description & Limitations** |
| --- | --- | --- |
| **Offline** | **PCAP (LibPCAP)** | Processes previously captured packet files. Ideal for post-incident investigations and safely testing new rule configurations. |
| **Live** | **LibPCAP** | Reads packets directly from network interfaces in real-time.<br>**Limitation:** Suffers from performance constraints and lacks load-balancing. |
| **Live** | **NFQ (Netfilter Queue)** | A *Linux-specific inline IPS mode* working with `IPTables` to route packets from the kernel for inspection.<br>**Requirement:** Needs active "drop rules" to block malicious packets. |
| **Live** | **AF_PACKET** | A high-performance, multi-threaded *alternative* to LibPCAP.<br>**Limitation:** *Incompatible with older Linux distributions* and *cannot be used inline* *if the host machine also routes packets*. |

### **Suricata Outputs**

Suricata generates various *logs, alerts, and network metadata* (like DNS requests and network flows). The two most notable formats are:

- **EVE (JSON):** The most critical output format. It acts as a comprehensive, JSON-formatted log that **records alerts, drops, and detailed metadata** (HTTP, DNS, TLS, flows). *Because it is JSON, it is easily ingested and analyzed by platforms like Logstash.*
- **Unified2:** A legacy, Snort-compatible binary alert format. It is primarily used to integrate with other software that relies on Snort's ecosystem and can be read using Snort’s `u2spewfoo` tool.

### **Configuring Suricata & Custom Rules**

we can get an overview of all the rule files by listing `/etc/suricata/rules/`:

```bash
$ ls -lah /etc/suricata/rules/
total 27M
drwxr-xr-x 2 root root 4.0K Jun 28 12:10 .
drwxr-xr-x 3 root root 4.0K Jul  4 14:44 ..
-rw-r--r-- 1 root root  31K Jun 27 20:55 3coresec.rules
-rw-r--r-- 1 root root 1.9K Jun 15 05:51 app-layer-events.rules
-rw-r--r-- 1 root root 2.1K Jun 27 20:55 botcc.portgrouped.rules
-rw-r--r-- 1 root root  27K Jun 27 20:55 botcc.rules
-rw-r--r-- 1 root root 109K Jun 27 20:55 ciarmy.rules
-rw-r--r-- 1 root root  12K Jun 27 20:55 compromised.rules
-rw-r--r-- 1 root root  21K Jun 15 05:51 decoder-events.rules
---SNIP---
```

We can use `more` (a tool help you view written content in pages) to read these rule:

```bash
$ more /etc/suricata/rules/emerging-malware.rules
# Emerging Threats
#
# This distribution may contain rules under two different licenses.
#
#  Rules with sids 1 through 3464, and 100000000 through 100000908 are under the GPLv2.
#  A copy of that license is available at http://www.gnu.org/licenses/gpl-2.0.html
#
#  Rules with sids 2000000 through 2799999 are from Emerging Threats and are covered under the BSD License
#  as follows:
#
#*************************************************************
#  Copyright (c) 2003-2022, Emerging Threats
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
#  following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following
#    disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
#    following disclaimer in the documentation and/or other materials provided with the distribution.
#  * Neither the name of the nor the names of its contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES,
#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
#  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#*************************************************************
#
#
#
#

# This Ruleset is EmergingThreats Open optimized for suricata-5.0-enhanced.

#alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Psyb0t joining an IRC Channel"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"
JOIN #mipsel"; reference:url,www.adam.com.au/bogaurd/PSYB0T.pdf; reference:url,doc.emergingthreats.net/2009172; classtype:trojan-activity; sid:2009172; rev:2; me
tadata:created_at 2010_07_30, updated_at 2010_07_30;)

alert tcp $HOME_NET any -> $EXTERNAL_NET 25 (msg:"ET MALWARE SC-KeyLog Keylogger Installed - Sending Initial Email Report"; flow:established,to_server; content:"
Installation of SC-KeyLog on host "; nocase; content:"<p>You will receive a log report every "; nocase; reference:url,www.soft-central.net/keylog.php; reference:
url,doc.emergingthreats.net/2002979; classtype:trojan-activity; sid:2002979; rev:4; metadata:created_at 2010_07_30, updated_at 2010_07_30;)

alert tcp $HOME_NET any -> $EXTERNAL_NET 25 (msg:"ET MALWARE SC-KeyLog Keylogger Installed - Sending Log Email Report"; flow:established,to_server; content:"SC-K
eyLog log report"; nocase; content:"See attached file"; nocase; content:".log"; nocase; reference:url,www.soft-central.net/keylog.php; reference:url,doc.emerging
threats.net/2008348; classtype:trojan-activity; sid:2008348; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
---SNIP---
```

Each rule usually involves specific variables, such as `$HOME_NET` and `$EXTERNAL_NET` 

The rule examines traffic from the IP addresses specified in the `$HOME_NET` variable heading towards the IP addresses in the `$EXTERNAL_NET` variable.

```bash
$ pwd
/etc/suricata
$ ls
classification.config  reference.config  suricata.log
eve.json	      rules		**suricata.yaml**
fast.log	      stats.log	threshold.config
```

**These variables can be defined in the `suricata.yaml` configuration file.**

```bash
$ more /etc/suricata/suricata.yaml
%YAML 1.1
---

# Suricata configuration file. In addition to the comments describing all
# options in this file, full documentation can be found at:
# https://suricata.readthedocs.io/en/latest/configuration/suricata-yaml.html

# This configuration file generated by Suricata 6.0.13.
suricata-version: "6.0"

##
## Step 1: Inform Suricata about your network
##

vars:
  # more specific is better for alert accuracy and performance
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
    #HOME_NET: "[192.168.0.0/16]"
    #HOME_NET: "[10.0.0.0/8]"
    #HOME_NET: "[172.16.0.0/12]"
    #HOME_NET: "any"

    EXTERNAL_NET: "!$HOME_NET"
    #EXTERNAL_NET: "any"

    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
---SNIP---
```

To configure Suricata to load a custom rules file we would use a text editor to edit `.yaml` file as follow:

```bash
$ sudo vim /etc/suricata/suricata.yaml
```

- Add `/home/htb-student/local.rules` to **rule-files:** section in `suricata.yaml`
- Press the `Esc` key
- Enter `:wq` and then, press the `Enter` key

![image.png](/assets/img/cdsa/sec9-working-with-ids-ips/image.png)

### **Hands-on With Suricata Inputs**

With Suricata inputs, we can experiment with both *offline* and *live* input:

#### #1. With offline input

To read network trafffic, we can use **`-r <path/to/file>`** switch

```bash
$ suricata -r /home/htb-student/pcaps/suspicious.pcap
18/6/2026 -- 05:14:55 - <Notice> - This is Suricata version 6.0.13 RELEASE running in USER mode
18/6/2026 -- 05:14:55 - <Notice> - all 3 packet processing threads, 4 management threads initialized, engine started.
18/6/2026 -- 05:14:55 - <Notice> - Signal Received.  Stopping engine.
18/6/2026 -- 05:14:55 - <Notice> - Pcap-file module read 1 files, 5172 packets, 3941260 bytes
```

Suricata will create various logs (mainly `eve.json`, `fast.log`, and `stats.log`).

```bash
$ ls /var/log/suricata/
certs  core  eve.json  fast.log  files	old_eve.json  old_fast.log  old_stats.log  stats.log  suricata.log  suricata-start.log
```

To make the JSON easy to read, use `jq '.'`

```bash
cat eve.json | jq '.'
```

An alternative command can be executed to bypass checksums (`-k` flag) and log in a different directory (`-l` flag)

```bash
$ suricata -r /home/htb-student/pcaps/suspicious.pcap -k none -l .
5/7/2023 -- 13:37:43 - <Notice> - This is Suricata version 6.0.13 RELEASE running in USER mode
5/7/2023 -- 13:37:43 - <Notice> - all 3 packet processing threads, 4 management threads initialized, engine started.
5/7/2023 -- 13:37:43 - <Notice> - Signal Received.  Stopping engine.
5/7/2023 -- 13:37:43 - <Notice> - Pcap-file module read 1 files, 5172 packets, 3941260 bytes
```

**`-k none` (Checksum Validation):** This flag require Suricata to ture off packet **checksum.**

**`-l .` (Log Directory):** This flag establish a directory to export log file (`.` mean the current folder)

#### #2. With live input (IDS Mode)

We can try Suricata’s (Live) `LibPCAP` mode

- List out all network interfaces with `ifconfig`
- Select an interface you want to monitor
- Turn the monitor on `sudo suricata --pcap=<interface>`

```bash
$ sudo suricata --pcap=ens160 -vv
[sudo] password for htb-student:
5/7/2023 -- 13:44:01 - <Notice> - This is Suricata version 6.0.13 RELEASE running in SYSTEM mode
5/7/2023 -- 13:44:01 - <Info> - CPUs/cores online: 2
**5/7/2023 -- 13:44:01 - <Info> - Setting engine mode to IDS mode by default**
5/7/2023 -- 13:44:01 - <Info> - Found an MTU of 1500 for 'ens160'
5/7/2023 -- 13:44:01 - <Info> - Found an MTU of 1500 for 'ens160'
**5/7/2023 -- 13:44:01 - <Info> - fast output device (regular) initialized: fast.log
5/7/2023 -- 13:44:01 - <Info> - eve-log output device (regular) initialized: eve.json
5/7/2023 -- 13:44:01 - <Info> - stats output device (regular) initialized: stats.log**
5/7/2023 -- 13:44:01 - <Info> - Running in live mode, activating unix socket
5/7/2023 -- 13:44:01 - <Perf> - using shared mpm ctx' for http_uri
5/7/2023 -- 13:44:01 - <Perf> - using shared mpm ctx' for http_uri
5/7/2023 -- 13:44:01 - <Perf> - using shared mpm ctx' for http_raw_uri
5/7/2023 -- 13:44:01 - <Perf> - using shared mpm ctx' for http_raw_uri
**5/7/2023 -- 13:44:01 - <Info> - 1 rule files processed. 1 rules successfully loaded, 0 rules failed**
5/7/2023 -- 13:44:01 - <Info> - Threshold config parsed: 0 rule(s) found
5/7/2023 -- 13:44:01 - <Perf> - using shared mpm ctx' for tcp-packet
5/7/2023 -- 13:44:01 - <Perf> - using shared mpm ctx' for tcp-stream
5/7/2023 -- 13:44:01 - <Perf> - using shared mpm ctx' for udp-packet
5/7/2023 -- 13:44:01 - <Perf> - using shared mpm ctx' for other-ip
5/7/2023 -- 13:44:01 - <Info> - 1 signatures processed. 0 are IP-only rules, 0 are inspecting packet payload, 1 inspect application layer, 0 are decoder event only
5/7/2023 -- 13:44:01 - <Perf> - TCP toserver: 1 port groups, 1 unique SGH's, 0 copies
5/7/2023 -- 13:44:01 - <Perf> - TCP toclient: 0 port groups, 0 unique SGH's, 0 copies
5/7/2023 -- 13:44:01 - <Perf> - UDP toserver: 1 port groups, 1 unique SGH's, 0 copies
5/7/2023 -- 13:44:01 - <Perf> - UDP toclient: 0 port groups, 0 unique SGH's, 0 copies
5/7/2023 -- 13:44:01 - <Perf> - OTHER toserver: 0 proto groups, 0 unique SGH's, 0 copies
5/7/2023 -- 13:44:01 - <Perf> - OTHER toclient: 0 proto groups, 0 unique SGH's, 0 copies
5/7/2023 -- 13:44:01 - <Perf> - Unique rule groups: 2
5/7/2023 -- 13:44:01 - <Perf> - Builtin MPM "toserver TCP packet": 0
5/7/2023 -- 13:44:01 - <Perf> - Builtin MPM "toclient TCP packet": 0
5/7/2023 -- 13:44:01 - <Perf> - Builtin MPM "toserver TCP stream": 0
5/7/2023 -- 13:44:01 - <Perf> - Builtin MPM "toclient TCP stream": 0
5/7/2023 -- 13:44:01 - <Perf> - Builtin MPM "toserver UDP packet": 0
5/7/2023 -- 13:44:01 - <Perf> - Builtin MPM "toclient UDP packet": 0
5/7/2023 -- 13:44:01 - <Perf> - Builtin MPM "other IP packet": 0
5/7/2023 -- 13:44:01 - <Perf> - AppLayer MPM "toserver dns_query (dns)": 1
5/7/2023 -- 13:44:01 - <Info> - Using 1 live device(s).
5/7/2023 -- 13:44:01 - <Info> - using interface ens160
5/7/2023 -- 13:44:01 - <Perf> - ens160: disabling rxcsum offloading
5/7/2023 -- 13:44:01 - <Perf> - ens160: disabling txcsum offloading
5/7/2023 -- 13:44:01 - <Info> - running in 'auto' checksum mode. Detection of interface state will require 1000ULL packets
5/7/2023 -- 13:44:01 - <Info> - Found an MTU of 1500 for 'ens160'
5/7/2023 -- 13:44:01 - <Info> - Set snaplen to 1524 for 'ens160'
5/7/2023 -- 13:44:01 - <Perf> - NIC offloading on ens160: RX unset TX unset
5/7/2023 -- 13:44:01 - <Perf> - NIC offloading on ens160: SG: unset, GRO: unset, LRO: unset, TSO: unset, GSO: unset
5/7/2023 -- 13:44:01 - <Info> - RunModeIdsPcapAutoFp initialised
5/7/2023 -- 13:44:01 - <Info> - Running in live mode, activating unix socket
5/7/2023 -- 13:44:01 - <Info> - Using unix socket file '/var/run/suricata/suricata-command.socket'
5/7/2023 -- 13:44:01 - <Notice> - all 3 packet processing threads, 4 management threads initialized, engine started.

```

We can also use Suricata in `IDS` mode with `AF_PACKET` input

Both `sudo suricata -i ens160` and `sudo suricata --af-packet=ens160` perform the exact same function.

**AF_PACKET:** It is a native Linux kernel technology that allows for extremely fast, direct packet capturing with much lower CPU usage compared to the older `LibPCAP` library.

**The `-i` Flag's Role:** When run on Linux, `-i` automatically defaults to the superior `AF_PACKET` mode. You only need to explicitly use the `--pcap` flag if you specifically want to force Suricata to use the older `LibPCAP` method.

#### #3. For Suricata in Inline (`NFQ`) mode (IPS Mode)

First we need to establish this `iptables` command

```bash
$ sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 
```

This mean all traffic **FORWARD** through this machine must not be forwarded directly; instead, it must be intercepted and sent to an **NFQUEUE (Netfilter Queue)** queue 0.

The second command is to enable **Suricata** to monitor this queue

```bash
$ sudo suricata -q 0
5/7/2023 -- 13:52:38 - <Notice> - This is Suricata version 6.0.13 RELEASE running in SYSTEM mode
5/7/2023 -- 13:52:39 - <Notice> - all 4 packet processing threads, 4 management threads initialized, engine started.
```

### **Hands-on With Suricata Outputs**

`/var/log/suricata` directory is where Suricata save logs. Among these logs, we find the `eve.json`, `fast.log`, and `stats.log` files.

- **eve.json**: This file is Suricata's recommended output and contains JSON objects, each carrying diverse information. You cant use `jq 'select(**<something>**)'` to select specific things on the file.

```bash
$ cat /var/log/suricata/old_eve.json | jq 'select(.event_type == "alert")'
{
  "timestamp": "2023-07-06T08:34:35.003163+0000",
  "flow_id": 1959965318909019,
  "in_iface": "ens160",
  "event_type": "alert",
  "src_ip": "10.9.24.101",
  "src_port": 51833,
  "dest_ip": "10.9.24.1",
  "dest_port": 53,
  "proto": "UDP",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1,
    "rev": 0,
    "signature": "Known bad DNS lookup, possible Dridex infection",
    "category": "",
    "severity": 3
  },
  "dns": {
    "query": [
      {
        "type": "query",
        "id": 6430,
        "rrname": "adv.epostoday.uk",
        "rrtype": "A",
        "tx_id": 0,
        "opcode": 0
      }
    ]
  },
  "app_proto": "dns",
  "flow": {
    "pkts_toserver": 1,
    "pkts_toclient": 0,
    "bytes_toserver": 76,
    "bytes_toclient": 0,
    "start": "2023-07-06T08:34:35.003163+0000"
  }
}
```

| **Field** | **Meaning** |
| --- | --- |
| timestamp | When the event occurred |
| *flow_id* | Unique identifier of the network flow |
| *event_type* | Type of event |
| *src_ip* | Source IP |
| *src_port* | Source port |
| *dest_ip* | Destination IP |
| *dest_port* | Destination port |
- **fast.log**: This is a text-based log format that records alerts only and is enabled by default.

```bash
$ cat /var/log/suricata/old_fast.log
07/06/2023-08:34:35.003163  [**] [1:1:0] Known bad DNS lookup, possible Dridex infection [**] [Classification: (null)] [Priority: 3] {UDP} 10.9.24.101:51833 -> 10.9.24.1:53
```

- **stats.log**: This is a human-readable statistics log, which can be particularly useful while debugging Suricata deployments.

```bash
$ cat /var/log/suricata/old_stats.log
------------------------------------------------------------------------------------
Date: 7/6/2023 -- 08:34:24 (uptime: 0d, 00h 00m 08s)
------------------------------------------------------------------------------------
Counter                                       | TM Name                   | Value
------------------------------------------------------------------------------------
capture.kernel_packets                        | Total                     | 4
decoder.pkts                                  | Total                     | 3
decoder.bytes                                 | Total                     | 212
decoder.ipv6                                  | Total                     | 1
decoder.ethernet                              | Total                     | 3
decoder.icmpv6                                | Total                     | 1
decoder.avg_pkt_size                          | Total                     | 70
decoder.max_pkt_size                          | Total                     | 110
flow.icmpv6                                   | Total                     | 1
flow.wrk.spare_sync_avg                       | Total                     | 100
flow.wrk.spare_sync                           | Total                     | 1
flow.mgr.full_hash_pass                       | Total                     | 1
flow.spare                                    | Total                     | 9900
tcp.memuse                                    | Total                     | 606208
tcp.reassembly_memuse                         | Total                     | 98304
flow.memuse                                   | Total                     | 7394304
------------------------------------------------------------------------------------
---SNIP---
```

> **Note:** Instead of relying on the massive, comprehensive `eve.json` file, Suricata can be configured to generate focused, protocol-specific logs (like `http.log`) to save storage space and simplify targeted network analysis.
> 
> 
> ![image.png](/assets/img/cdsa/sec9-working-with-ids-ips/image%201.png)
> 

### **Hands-on With Suricata Outputs - File Extraction**

Suricata has **[file extraction](https://docs.suricata.io/en/suricata-6.0.13/file-extraction/file-extraction.html)** feature allows us to capture and store files transferred.

First, tell Suricata how to handle extracted files by editing the `suricata.yaml` configuration file. Locate the `file-store` section and apply the following settings:

```bash
file-store:
  version: 2
  enabled: yes
  force-filestore: yes
```

In the same `file-store` section, we define where Suricata stores the extracted files. We set the `dir` option to the directory of our choice (I’m let it be default).

![image.png](/assets/img/cdsa/sec9-working-with-ids-ips/image%202.png)

File extraction does not happen automatically. You must give Suricata explicit instructions by writing a rule. (rule for only filestore).

```bash
alert http any any -> any any (msg:"FILE store all"; **filestore**; sid:2; rev:1;)
```

When the file is being extracted, it will be saved in a hash-based directory structure, you can . You can list all of them by using:

```bash
$ sudo find <folder_name> -type f 
<folder_name>/fb/fb20d18d00c806deafe14859052072aecfb9f46be6210acfce80289740f2e20e
<folder_name>/21/214306c98a3483048d6a69eec6bf3b50497363bc2c98ed3cd954203ec52455e5
<folder_name>/21/21742fc621f83041db2e47b0899f5aea6caa00a4b67dbff0aae823e6817c5433
<folder_name>/26/2694f69c4abf2471e09f6263f66eb675a0ca6ce58050647dcdcfebaf69f11ff4
<folder_name>/2c/2ca1a0cd9d8727279f0ba99fd051e1c0acd621448ad4362e1c9fc78700015228
<folder_name>/7d/7d4c00f96f38e0ffd89bc2d69005c4212ef577354cc97d632a09f51b2d37f877
<folder_name>/6b/6b7fee8a4b813b6405361db2e70a4f5a213b34875dd2793667519117d8ca0e4e
<folder_name>/2e/2e2cb2cac099f08bc51abba263d9e3f8ac7176b54039cc30bbd4a45cfa769018
<folder_name>/50/508c47dd306da3084475faae17b3acd5ff2700d2cd85d71428cdfaae28c9fd41
<folder_name>/c2/c210f737f55716a089a33daf42658afe771cfb43228ffa405d338555a9918815
<folder_name>/ea/ea0936257b8d96ee6ae443adee0f3dacc3eff72b559cd5ee3f9d6763cf5ee2ab
<folder_name>/1a/1aab7d9c153887dfa63853534f684e5d46ecd17ba60cd3d61050f7f231c4babb
<folder_name>/c4/c4775e980c97b162fd15e0010663694c4e09f049ff701d9671e1578958388b9f
<folder_name>/63/63de4512dfbd0087f929b0e070cc90d534d6baabf2cdfbeaf76bee24ff9b1638
<folder_name>/48/482d9972c2152ca96616dc23bbaace55804c9d52f5d8b253b617919bb773d3bb
<folder_name>/8e/8ea3146c676ba436c0392c3ec26ee744155af4e4eca65f4e99ec68574a747a14
<folder_name>/8e/8e23160cc504b4551a94943e677f6985fa331659a1ba58ef01afb76574d2ad7c
<folder_name>/a5/a52dac473b33c22112a6f53c6a625f39fe0d6642eb436e5d125342a24de4458l
```

And then using `xxd` to peak inside the file:

```bash
$ sudo xxd <folder_name>/21/21742fc621f83041db2e47b0899f5aea6caa00a4b67dbff0aae823e6817c5433 | head
00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ..............
00000010: b800 0000 0000 0000 4000 0000 e907 0000  ........@.......
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 8000 0000  ................
00000040: 0e1f ba0e 00b4 09cd 21b8 014c cd21 5468  ........!..L.!Th
00000050: 6973 2070 726f 6772 616d 2063 616e 6e6f  is program canno
00000060: 7420 6265 2072 756e 2069 6e20 444f 5320  t be run in DOS 
00000070: 6d6f 6465 2e0d 0d0a 2400 0000 0000 0000  mode....$.......
00000080: 5045 0000 4c01 0300 fc90 8448 0000 0000  PE..L......H....
00000090: 0000 0000 e000 0f01 0b01 0600 00d0 0000  ................
```

In this case, the file was a *Windows executable* based on the file's header. More about the MS-DOS EXE format can be found in following resource [MZ](https://wiki.osdev.org/MZ).

### **Live Rule Reloading Feature & Updating Suricata Rulesets**

Live rule reloading allows us to update our ruleset without interrupting ongoing traffic inspection.

In the `suricata.yaml` file, we should locate the `detect-engine` section and set the value of the `reload` parameter to `true`.

```bash
detect-engine:
  - reload: true
```

If is not there, just add it in.

### **Validating Suricata's Configuration**

To validate the configuration, we can use the `-T` option provided by the Suricata command. This command runs a test to check if the configuration file is valid and all files referenced in the configuration are accessible.

```bash
$ sudo suricata -T -c /etc/suricata/suricata.yaml
18/6/2026 -- 12:06:52 - <Info> - Running suricata under test mode
18/6/2026 -- 12:06:52 - <Notice> - This is Suricata version 6.0.13 RELEASE running in SYSTEM mode
18/6/2026 -- 12:06:53 - <Notice> - Configuration provided was successfully loaded. Exiting.
```

### **Suricata Documentation**

[Suricata's documentation](https://docs.suricata.io/)

## Suricata Rule Development Part 1

### **Suricata Rule Anatomy**

Here is a structure of Suricata rule

```bash
action protocol from_ip port -> to_ip port (msg:"Known malicious behavior, possible X malware infection"; content:"some thing"; content:"some other thing"; sid:10000001; rev:1;)
```

#### **#1 Core Rule Structure & Components**

| **Category** | **Component / Keyword** | **Description** | **Examples / Usage** |
| --- | --- | --- | --- |
| **Header** | **Action** | Instructs Suricata on what to do when a match occurs. | `alert`, `log`, `pass`, `drop`, `reject` |
|  | **Protocol** | The network protocol where the rule is evaluated. | `tcp`, `udp`, `icmp`, `ip`, `http`, `tls`, `dns` |
|  | **Directionality** | Arrows indicating the traffic flow between source and destination IPs/Ports. | `->` (One-way)<br>`<>` (Bidirectional) |
|  | **Ports** | The specific ports where traffic is evaluated. | `80`, `[8443,8080,!8443]`, `$UNCOMMON_PORTS` |
| **Message & Content** | **`msg`** | The human-readable alert message displayed to analysts. | `msg:"SSH connection attempt";` |
|  | **`flow`** | Identifies the originator/responder and monitors session states (e.g., "established"). | `flow:to_server, established;` |
|  | **`dsize`** | Matches based on the payload size (TCP segment length). | `dsize:>10000;` |
|  | **`content`** | The exact byte sequences or strings Suricata searches for in the payload. | `content:"image/gif";`<br>`content:" |
|  | **Rule Buffers** | Targets specific packet segments to save time/resources instead of searching everything. | `http.accept;`, `http_method;`, `http_uri;` |
| **Rule Options** | **`nocase`** | Makes the preceding content match case-insensitive. | `content:"User-Agent"; nocase;` |
|  | **`offset`** | Defines the exact starting byte position for a content match within the payload. | `offset:0; depth:5;` |
|  | **`distance`** | The minimum bytes to skip *after* a previous match before searching for the next. | `distance:10;` |
|  | **`within`** | The maximum byte window to search in *after* the `distance` anchor point. | `within:80;` |
| **Metadata** | **`sid`** | Signature ID; a unique numeric identifier for the rule. | `sid:10000001;` |
|  | **`rev`** | Revision number; tracks the evolution/version of the rule. | `rev:1;` |
|  | **`reference`** | Provides a link or trail back to the source information that inspired the rule. | `reference:url,example.com;` |

When you write a new rule yourself, you cannot just pick random `sid` numbers (like `sid:1` or `sid:2`) because they will conflict with existing system rules. The `sid` numbers are divided into the following ranges:

- **From 1 to 999,999:** The zone reserved exclusively for the default rules built into the Snort/Suricata software itself. (You should not use this range).
- **From 1,000,000 to 1,999,999:** The free zone dedicated to **Local rules** (custom/self-written rules). When creating a rule for your company or doing an exercise, you should start picking numbers from 1 million upwards (e.g., `sid:1000001;`).
- **From 2,000,000 and above:** The zone for professional Rule providers (such as Emerging Threats - ET, Abuse.ch). For example, the rule catching Dridex had the `sid` 2023476, just by seeing that it falls in the 2 million range, you instantly know it was downloaded from a well-known, professional repository.

#### **PCRE (Perl Compatible Regular Expression) Breakdown**

PCRE allows for advanced pattern matching using regular expressions. It should be enclosed in slashes (e.g., `/pattern/flags`) and should generally be used alongside `content` matches for performance.

**Example Pattern Analyzed:** `!"/^\$?[\sa-z\\_0-9.-]*(\&|$)/iRP"`

| **Character / Flag** | **Meaning in this Regex** |
| --- | --- |
| **`!`** | **Inverted match:** Triggers only when the pattern is *not* found. |
| **`/ ... /`** | The boundaries encasing the regular expression. |
| **`^`** | **Anchor:** Matches the start of the line/buffer. |
| **`\$?`** | Checks for an optional literal dollar sign (`$`) at the start. |
| **`[ ... ]*`** | Matches zero or more (`*`) of any characters defined inside the brackets. |
| **`\s`** | Matches a space character. |
| **`a-z`** | Matches any lowercase letter. |
| **`\\`** | Matches a literal backslash. |
| **`_0-9.-`** | Matches an underscore, any digit, a period, or a hyphen. |
| **`(\&|$)`** | Matches either a literal ampersand (`&`) **OR** (`|`) the end of the line (`$`). |
| **`i`** | **Flag:** Makes the regex case-insensitive. |
| **`R`** | **Flag:** Makes the match relative to the previous match. |
| **`P`** | **Flag:** Inspects the specific HTTP buffer requested (matches with rule buffers like `http_client_body`). |

### **IDS/IPS Rule Development Approaches**

#### #1. Choosing Your Approach

- **Signature-based Detection:** You are looking for specific, known evidence of malware.
    - Highly precise for known threats, but bad at catching zero-days.
    - You use exact string matches like `content:"malicious_string";` or advanced regex with `pcre:"/regex/"`.
- **Anomaly/Behavior-based Detection:** You aren't looking for a specific file, but rather weird behavior (e.g., a massive data transfer or using a strange port).
    - Great for catching new, unknown threats, but generates more false positives.
    - You set *unusual ports* in the header (e.g., `> $HOME_NET $UNCOMMON_PORTS`) or use measurement keywords to detect *payload larger than usual* like `dsize:>10000;`.
- **Stateful Protocol Analysis:** You are checking if the connection behaves according to the rules of normal network traffic (baseline).
    - Tracks the state of the connection to identify unexpected deviations.
    - You use the `flow` keyword to **monitor session states**, such as `flow:established, to_server;` (only inspect traffic if a valid connection was already made).

#### #2. The Rule Structure

No matter which strategy you chose above, when it's time to write the rule, read it from left to right using this template:

> **[Action] [Protocol] [Src IP] [Port] -> [Dest IP] [Port] ( msg:"Description"; content:"Keyword"; [Position Modifiers]; sid:Number; rev:1; )**
> 
- **WHO & WHERE:** Who is traveling, where are they going, and how?
    - *Example:* `alert tcp $EXTERNAL_NET any -> $HOME_NET 80`
- **WHAT:** Name the alert so your analyst team knows immediately what happened.
    - *Example:* `msg:"Detected backdoor access attempt";`
- **WHAT TO FIND & HOW:** What exact evidence are you looking for, and where should Suricata look to save time?
    - *Example:* `content:"/login.php"; nocase; http_uri;` (Look for the text "/login.php", ignore capitalization, and only search inside the URL path).
- **WRITE IT DOWN:** Assign a tracking number.
    - *Example:* `sid:100001; rev:1;`

#### #3. Three Golden Rules for Writing

1. **Copy and Tweak:** Nobody writes a rule from a blank page. Always find an existing, working rule (like from Emerging Threats) that closely matches your goal. Copy it, then modify the IPs, Ports, and `content` fields to suit your needs.
2. **Limit the Scope for Performance:** If you force Suricata to blindly scan every byte of every packet, your network will slow down. Always pair your `content` matches with position modifiers like `http_uri`, `http_client_body`, or use `offset` (where to start looking) and `depth` (how far to look).
3. **Regex is a Last Resort:** PCRE uses a massive amount of CPU. Only use it when standard content matching fails (like finding randomized malware strings). If you *must* use regex, always put a fast, simple `content` match before the `pcre` statement so Suricata can filter out harmless traffic before doing the heavy lifting.

### **Suricata Rule Development Example 1: Detecting PowerShell Empire**

The Suricata rule below is designed to detect possible outbound activity from [PowerShell Empire](https://github.com/EmpireProject/Empire), a common post-exploitation framework used by attackers.

```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Possible PowerShell Empire Activity Outbound"; flow:established,to_server; content:"GET"; http_method; content:"/"; http_uri; depth:1; pcre:"/^(?:login\/process|admin\/get|news)\.php$/RU"; content:"session="; http_cookie; pcre:"/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=|[A-Z0-9+/]{4})$/CRi"; content:"Mozilla|2f|5.0|20 28|Windows|20|NT|20|6.1"; http_user_agent; http_start; content:".php|20|HTTP|2f|1.1|0d 0a|Cookie|3a 20|session="; fast_pattern; http_header_names; content:!"Referer"; content:!"Cache"; content:!"Accept"; sid:2027512; rev:1;)
```

### **Suricata Rule Development Example 2: Detecting Covenant**

```bash
alert tcp any any -> $HOME_NET any (msg:"detected by body"; content:"<title>Hello World!</title>"; detection_filter: track by_src, count 4 , seconds 10; priority:1; sid:3000011;)
```

**Rule source**: [Signature-based IDS for Encrypted C2 Traffic Detection - Eduardo Macedo](https://repositorio-aberto.up.pt/bitstream/10216/142718/2/572020.pdf)

The (inefficient) Suricata rule above is designed to detect certain variations of [Covenant](https://github.com/cobbr/Covenant), another common post-exploitation framework used by attackers.

### **Suricata Rule Development Example 3: Detecting Covenant (Using Analytics)**

```bash
alert tcp $HOME_NET any -> any any (msg:"detected by size and counter"; dsize:312; detection_filter: track by_src, count 3 , seconds 10; priority:1; sid:3000001;)
```

This Suricata rule is designed to generate a high-priority alert if it detects at least three instances of TCP traffic within ten seconds that each contain a data payload of exactly 312 bytes, all originating from the same source IP within our network and headed anywhere.

### **Suricata Rule Development Example 4: Detecting Sliver**

```bash
alert tcp any any -> any any (msg:"Sliver C2 Implant Detected"; content:"POST"; pcre:"/\/(php|api|upload|actions|rest|v1|oauth2callback|authenticate|oauth2|oauth|auth|database|db|namespaces)(.*?)((login|signin|api|samples|rpc|index|admin|register|sign-up)\.php)\?[a-z_]{1,2}=[a-z0-9]{1,10}/i"; sid:1000007; rev:1;)
```

**Rule source**: [https://www.bilibili.com/read/cv19510951/](https://www.bilibili.com/read/cv19510951/)

The Suricata rule above is designed to detect certain variations of [Sliver](https://github.com/BishopFox/sliver), yet another common post-exploitation framework used by attackers.

## Suricata Rule Development Part 2 (Encrypted Traffic)

By examining the plaintext details of SSL/TLS certificates, such as *the issuer* and *domain information*, security systems can identify anomalous or suspicious infrastructure. 

Additionally, utilizing **JA3 fingerprinting** creates *a unique hash from the client's initial handshake request*, allowing defenders to reliably identify and block specific malware families even when the actual payload is hidden.

![image.png](/assets/img/cdsa/sec9-working-with-ids-ips/image%203.png)

### **Suricata Rule Development Example 5: Detecting Dridex (TLS Encrypted)**

```bash
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE ABUSE.CH SSL Blacklist Malicious SSL certificate detected (Dridex)"; flow:established,from_server; content:"|16|"; content:"|0b|"; within:8; byte_test:3,<,1200,0,relative; content:"|03 02 01 02 02 09 00|"; fast_pattern; content:"|30 09 06 03 55 04 06 13 02|"; distance:0; pcre:"/^[A-Z]{2}/R"; content:"|55 04 07|"; distance:0; content:"|55 04 0a|"; distance:0; pcre:"/^.{2}[A-Z][a-z]{3,}\s(?:[A-Z][a-z]{3,}\s)?(?:[A-Z](?:[A-Za-z]{0,4}?[A-Z]|(?:\.[A-Za-z]){1,3})|[A-Z]?[a-z]+|[a-z](?:\.[A-Za-z]){1,3})\.?[01]/Rs"; content:"|55 04 03|"; distance:0; byte_test:1,>,13,1,relative; content:!"www."; distance:2; within:4; pcre:"/^.{2}(?P<CN>(?:(?:\d?[A-Z]?|[A-Z]?\d?)(?:[a-z]{3,20}|[a-z]{3,6}[0-9_][a-z]{3,6})\.){0,2}?(?:\d?[A-Z]?|[A-Z]?\d?)[a-z]{3,}(?:[0-9_-][a-z]{3,})?\.(?!com|org|net|tv)[a-z]{2,9})[01].*?(?P=CN)[01]/Rs"; content:!"|2a 86 48 86 f7 0d 01 09 01|"; content:!"GoDaddy"; sid:2023476; rev:5;)
```

The rule above triggers an alert upon detecting a TLS session from the **external network** to the **home network**, where the payload of the session contains specific byte patterns and meets several conditions. These patterns and conditions correspond to SSL certificates that have been linked to certain variations of the **Dridex trojan**, as referenced by the SSL blacklist on `abuse.ch`

### **Suricata Rule Development Example 6: Detecting Sliver (TLS Encrypted)**

```bash
alert tls any any -> any any (msg:"Sliver C2 SSL"; ja3.hash; content:"473cd7cb9faa642487833865d516e578"; sid:1002; rev:1;)
```

The Suricata rule above is designed to detect certain variations of [Sliver](https://github.com/BishopFox/sliver) whenever it identifies a TLS connection with a specific JA3 hash.

The JA3 hash can be calculated by using `ja3` tool.

```bash
**$ ja3 -a --json /home/htb-student/pcaps/sliverenc.pcap**
[
    {
        "destination_ip": "23.152.0.91",
        "destination_port": 443,
        "ja3": "771,49195-49199-49196-49200-52393-52392-49161-49171-49162-49172-156-157-47-53-49170-10-4865-4866-4867,0-5-10-11-13-65281-18-43-51,29-23-24-25,0",
        "ja3_digest": "473cd7cb9faa642487833865d516e578",
        "source_ip": "10.10.20.101",
        "source_port": 53222,
        "timestamp": 1634749464.600896
    },
    {
        "destination_ip": "23.152.0.91",
        "destination_port": 443,
        "ja3": "771,49195-49199-49196-49200-52393-52392-49161-49171-49162-49172-156-157-47-53-49170-10-4865-4866-4867,0-5-10-11-13-65281-18-43-51,29-23-24-25,0",
        "ja3_digest": "473cd7cb9faa642487833865d516e578",
        "source_ip": "10.10.20.101",
        "source_port": 53225,
        "timestamp": 1634749465.069819
    },
    {
        "destination_ip": "23.152.0.91",
        "destination_port": 443,
        "ja3": "771,49195-49199-49196-49200-52393-52392-49161-49171-49162-49172-156-157-47-53-49170-10-4865-4866-4867,0-5-10-11-13-65281-18-43-51,29-23-24-25,0",
        "ja3_digest": "473cd7cb9faa642487833865d516e578",
        "source_ip": "10.10.20.101",
        "source_port": 53229,
        "timestamp": 1634749585.240773
    },
---SNIP---
```

# Snort

## Snort Fundamentals

Snort is an open-source tool, which serves as both an *Intrusion Detection System (IDS)* and *Intrusion Prevention System (IPS)*, but can also function as a *packet logger or sniffer*, akin to Suricata.

### **Snort Operation Modes**

- Inline IDS/IPS (block traffic)
- Passive IDS (observe and detect traffic)
- Network-based IDS
- Host-based IDS (not ideally)

**`-r` (Read):** You hand Snort a `.pcap` file. Snort will watches and writes a report about anything shady it saw.

**`-i` (Interface):** You tell Snort to watch a live network cable (like `eth0`).

**`-Q` (Inline):** This flag tells Snort to actually **drop any bad packets.

**DAQ (Data Acquisition)** is the underlying technology that decides *how* Snort gets its hands on the network traffic.

**`afpacket`** is the name of a specific DAQ tool used in Linux. It acts like a special pair of gloves that allows Snort to directly grab, inspect, and drop live network packets as they arrive at the Linux network card.

### **Snort Architecture**

| **Component** | **Function** | **Input** | **Output** |
| --- | --- | --- | --- |
| **Packet Sniffer (Packet Decoder)** | *Captures* network traffic and *recognizes the structure* of each packet. | Raw network packets from the network interface. | Decoded packets forwarded to the **Preprocessors**. |
| **Preprocessors** | Analyze packets to *identify their type, behavior, or anomalies before rule inspection*.<br>**Configured in `snort.lua`.** | Decoded packets from the Packet Sniffer. | Processed packet information forwarded to the **Detection Engine**. |
| **Detection Engine** | *Compares* packets against the *configured Snort ruleset* to determine whether suspicious activity is present. | Processed packet data from the Preprocessors. | Matching events forwarded to the **Logging and Alerting System**. |
| **Logging and Alerting System** | *Records events and generates alerts* according to the actions specified in Snort rules. | Events generated by the Detection Engine. | Log entries and security alerts. |
| **Output Modules** | Determine how and where logs and alerts are stored or transmitted.<br>**Configured in `snort.lua`.** | Alerts and log data from the Logging and Alerting System. | Output to `syslog`, `unified2 files`, `databases`, or other configured destinations. |

### **Snort Configuration & Validating Snort's Configuration**

| **Section** | **Role in the Security Pipeline** |
| --- | --- |
| **Network Variables** | Defines your "Home" vs. "External" networks. |
| **Decoder Config** | Dictates how to deconstruct incoming raw packets (Ethernet, IP, TCP, etc.). |
| **Base Detection Engine** | Manages how Snort matches traffic patterns against the rule database. |
| **Dynamic Library Config** | Allows you to load modular plugins (shared objects) to add features without needing to recompile the whole Snort source code. |
| **Preprocessor Config** | Normalizes traffic (e.g., reassembling fragmented TCP streams or decoding HTTP) so the detection engine can understand the full context. |
| **Output Plugin Config** | Decides if alerts go to the console, a flat log file, or a database (like Elasticsearch or SQL). |
| **Rule Set Customization** | Tells Snort which specific sets of threat intelligence signatures to load and enforce. |
| **Decoder/Preprocessor Rules** | Specific rules for spotting malformed packets or evasion techniques used by attackers to sneak past the decoder. |
| **Shared Object Rules** | Advanced, pre-compiled rules that are often faster or allow for more complex detection logic than standard text-based rules. |
- **`snort_defaults.lua`**: Contains predefined paths (like where rules are stored) and standard variables. (Don't edit this file directly → leave it as your baseline.)
- **`snort.lua`**: You use this file to override the defaults and implement your specific security policy.

#### Pro-Tips

1. **Test Before You Run:** Never restart your production service without validating your config first. Use the `T` flag to check for syntax errors:
    
    `snort -c /path/to/snort.lua -T` 
    
    `-c` for configuration. 
    
    `-T` runs Snort in **test mode**
    
    *If it returns "Snort successfully validated the configuration," you are good to go.*
    
2. **Modularize:** If your configuration gets too large, you can create separate Lua files and use the `include` function in `snort.lua` to keep things organized.
3. **Start with the Network:** Always prioritize configuring your `HOME_NET` variable correctly. If Snort doesn't know what your network looks like, all the advanced detection rules will be much less effective.

```bash
**$ sudo more /root/snorty/etc/snort/snort.lua**
---------------------------------------------------------------------------
-- Snort++ configuration
---------------------------------------------------------------------------

-- there are over 200 modules available to tune your policy.
-- many can be used with defaults w/o any explicit configuration.
-- use this conf as a template for your specific configuration.

-- 1. configure defaults
-- 2. configure inspection
-- 3. configure bindings
-- 4. configure performance
-- 5. configure detection
-- 6. configure filters
-- 7. configure outputs
-- 8. configure tweaks

---------------------------------------------------------------------------
-- 1. configure defaults
---------------------------------------------------------------------------

-- HOME_NET and EXTERNAL_NET must be set now
-- setup the network addresses you are protecting
HOME_NET = 'any'

-- set up the external network addresses.
-- (leave as "any" in most situations)
EXTERNAL_NET = 'any'

include 'snort_defaults.lua'

---------------------------------------------------------------------------
-- 2. configure inspection
---------------------------------------------------------------------------

-- mod = { } uses internal defaults
-- you can see them with snort --help-module mod

-- mod = default_mod uses external defaults
-- you can see them in snort_defaults.lua

-- the following are quite capable with defaults:

stream = { }
stream_ip = { }
stream_icmp = { }
stream_tcp = { }
stream_udp = { }
stream_user = { }
stream_file = { }
---SNIP---

```

In Snort 3, everything is a **module**. Whether it's a protocol analyzer (like `http_inspect`), a logger (like `alert_json`), or a detection inspector (like `arp_spoof`), they all follow the same pattern

- **Discovery:** Use `snort --help-modules` to see what is available in your build.

```bash
**$ snort --help-modules**
ack (ips_option): rule option to match on TCP ack numbers
active (basic): configure responses
address_space_selector (policy_selector): configure traffic processing based on address space
alert_csv (logger): output event in csv format
alert_fast (logger): output event with brief text format
alert_full (logger): output event with full packet dump
alert_json (logger): output event in json format
alert_syslog (logger): output event to syslog
alert_talos (logger): output event in Talos alert format
alert_unixsock (logger): output event over unix socket
alerts (basic): configure alerts
appid (inspector): application and service identification
appids (ips_option): detection option for application ids
arp (codec): support for address resolution protocol
arp_spoof (inspector): detect ARP attacks and anomalies
---SNIP---
```

- **Inspection:** Use `snort --help-config <module_name>` to see the specific parameters you can tune for that module.

```bash
**$ snort --help-config arp_spoof**
ip4 arp_spoof.hosts[].ip: host ip address
mac arp_spoof.hosts[].mac: host mac address
```

- **Implementation:** Define these modules in `snort.lua` using **Lua tables**.

To validating configuration files to Snort, use

```bash
**$ snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq**
--------------------------------------------------
o")~   Snort++ 3.1.64.0
--------------------------------------------------
Loading /root/snorty/etc/snort/snort.lua:
Loading snort_defaults.lua:
Finished snort_defaults.lua:
        output
        ips
        classifications
        references
        binder
        file_id
        ftp_server
        smtp
        port_scan
        gtp_inspect
        dce_smb
        s7commplus
        modbus
        ssh
        active
        alerts
        daq
        decode
        host_cache
        host_tracker
        hosts
        network
        packets
        process
        search_engine
        so_proxy
        stream_icmp
        normalizer
        stream
        stream_ip
        stream_tcp
        stream_udp
        stream_user
        stream_file
        arp_spoof
        back_orifice
        dns
        imap
        netflow
        pop
        rpc_decode
        sip
        ssl
        telnet
        cip
        dnp3
        iec104
        mms
        dce_tcp
        dce_udp
        dce_http_proxy
        dce_http_server
        ftp_client
        ftp_data
        http_inspect
        http2_inspect
        file_policy
        js_norm
        appid
        wizard
        trace
Finished /root/snorty/etc/snort/snort.lua:
Loading file_id.rules_file:
Loading file_magic.rules:
Finished file_magic.rules:
Finished file_id.rules_file:
--------------------------------------------------
ips policies rule stats
              id  loaded  shared enabled    file
               0     208       0     208    /root/snorty/etc/snort/snort.lua
--------------------------------------------------
rule counts
       total rules loaded: 208
               text rules: 208
            option chains: 208
            chain headers: 1
--------------------------------------------------
service rule counts          to-srv  to-cli
                  file_id:      208     208
                    total:      208     208
--------------------------------------------------
fast pattern groups
                to_server: 1
                to_client: 1
--------------------------------------------------
search engine (ac_bnfa)
                instances: 2
                 patterns: 416
            pattern chars: 2508
               num states: 1778
         num match states: 370
             memory scale: KB
             total memory: 68.5879
           pattern memory: 18.6973
        match list memory: 27.3281
        transition memory: 22.3125
appid: MaxRss diff: 3084
appid: patterns loaded: 300
--------------------------------------------------
pcap DAQ configured to passive.

Snort successfully validated the configuration (with 0 warnings).
o")~   Snort exiting
```

**LibDAQ** is the "Data Acquisition Library." It is an abstraction layer that allows Snort to communicate with different network sources (hardware NICs, virtual bridges, or packet capture files).

`--daq-dir` told Snort where to identify the DAQ (Data Acquisition) modules installed on the system.

`-c` for configuration. 

### **Snort Inputs**

Use `.pcap` file with `-r`: 

```bash
**$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/icmp.pcap**

--------------------------------------------------
o")~   Snort++ 3.1.64.0
--------------------------------------------------
Loading /root/snorty/etc/snort/snort.lua:
Loading snort_defaults.lua:
Finished snort_defaults.lua:
---SNIP---
Finished /root/snorty/etc/snort/snort.lua:
Loading file_id.rules_file:
Loading file_magic.rules:
Finished file_magic.rules:
Finished file_id.rules_file:
--------------------------------------------------
ips policies rule stats
              id  loaded  shared enabled    file
               0     208       0     208    /root/snorty/etc/snort/snort.lua
--------------------------------------------------
rule counts
       total rules loaded: 208
               text rules: 208
            option chains: 208
            chain headers: 1
--------------------------------------------------
service rule counts          to-srv  to-cli
                  file_id:      208     208
                    total:      208     208
--------------------------------------------------
fast pattern groups
                to_server: 1
                to_client: 1
--------------------------------------------------
search engine (ac_bnfa)
                instances: 2
                 patterns: 416
            pattern chars: 2508
               num states: 1778
         num match states: 370
             memory scale: KB
             total memory: 68.5879
           pattern memory: 18.6973
        match list memory: 27.3281
        transition memory: 22.3125
appid: MaxRss diff: 3024
appid: patterns loaded: 300
--------------------------------------------------
pcap DAQ configured to read-file.
Commencing packet processing
++ [0] /home/htb-student/pcaps/icmp.pcap
-- [0] /home/htb-student/pcaps/icmp.pcap
--------------------------------------------------
Packet Statistics
--------------------------------------------------
daq
                    pcaps: 1
                 received: 8
                 analyzed: 8
                    allow: 8
                 rx_bytes: 592
--------------------------------------------------
codec
                    total: 8            (100.000%)
                      eth: 8            (100.000%)
                    icmp4: 8            (100.000%)
                     ipv4: 8            (100.000%)
--------------------------------------------------
Module Statistics
--------------------------------------------------
appid
                  packets: 8
        processed_packets: 8
           total_sessions: 1
--------------------------------------------------
binder
                new_flows: 1
                 inspects: 1
--------------------------------------------------
detection
                 analyzed: 8
--------------------------------------------------
port_scan
                  packets: 8
                 trackers: 2
--------------------------------------------------
stream
                    flows: 1
--------------------------------------------------
stream_icmp
                 sessions: 1
                      max: 1
                  created: 1
                 released: 1
--------------------------------------------------
Summary Statistics
--------------------------------------------------
timing
                  runtime: 00:00:00
                  seconds: 0.033229
                 pkts/sec: 241
o")~   Snort exiting
```

listen on *active network interfaces* with `-i`: **

```bash
**$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -i ens160**
--------------------------------------------------
o")~   Snort++ 3.1.64.0
--------------------------------------------------
Loading /root/snorty/etc/snort/snort.lua:
Loading snort_defaults.lua:
Finished snort_defaults.lua:
---SNIP---
Finished /root/snorty/etc/snort/snort.lua:
Loading file_id.rules_file:
Loading file_magic.rules:
Finished file_magic.rules:
Finished file_id.rules_file:
--------------------------------------------------
ips policies rule stats
              id  loaded  shared enabled    file
               0     208       0     208    /root/snorty/etc/snort/snort.lua
--------------------------------------------------
rule counts
       total rules loaded: 208
               text rules: 208
            option chains: 208
            chain headers: 1
--------------------------------------------------
service rule counts          to-srv  to-cli
                  file_id:      208     208
                    total:      208     208
--------------------------------------------------
fast pattern groups
                to_server: 1
                to_client: 1
--------------------------------------------------
search engine (ac_bnfa)
                instances: 2
                 patterns: 416
            pattern chars: 2508
               num states: 1778
         num match states: 370
             memory scale: KB
             total memory: 68.5879
           pattern memory: 18.6973
        match list memory: 27.3281
        transition memory: 22.3125
appid: MaxRss diff: 2820
appid: patterns loaded: 300
--------------------------------------------------
pcap DAQ configured to passive.
Commencing packet processing
++ [0] ens160
^C** caught int signal
== stopping
-- [0] ens160
--------------------------------------------------
Packet Statistics
--------------------------------------------------
daq
                 received: 33
                 analyzed: 33
                    allow: 33
                     idle: 9
                 rx_bytes: 2756
--------------------------------------------------
codec
                    total: 33           (100.000%)
                 discards: 2            (  6.061%)
                      arp: 13           ( 39.394%)
                      eth: 33           (100.000%)
                    icmp4: 12           ( 36.364%)
                    icmp6: 3            (  9.091%)
                     ipv4: 17           ( 51.515%)
                     ipv6: 3            (  9.091%)
                      tcp: 5            ( 15.152%)
--------------------------------------------------
Module Statistics
--------------------------------------------------
appid
                  packets: 18
        processed_packets: 16
          ignored_packets: 2
           total_sessions: 3
--------------------------------------------------
arp_spoof
                  packets: 13
--------------------------------------------------
binder
              raw_packets: 15
                new_flows: 3
                 inspects: 18
--------------------------------------------------
detection
                 analyzed: 33
--------------------------------------------------
port_scan
                  packets: 20
                 trackers: 8
--------------------------------------------------
stream
                    flows: 3
--------------------------------------------------
stream_icmp
                 sessions: 2
                      max: 2
                  created: 2
                 released: 2
--------------------------------------------------
stream_tcp
                 sessions: 1
                      max: 1
                  created: 1
                 released: 1
             instantiated: 1
                   setups: 1
            data_trackers: 1
              segs_queued: 1
            segs_released: 1
                 max_segs: 1
                max_bytes: 64
--------------------------------------------------
tcp
        bad_tcp4_checksum: 2
--------------------------------------------------
Appid Statistics
--------------------------------------------------
detected apps and services
              Application: Services   Clients    Users      Payloads   Misc       Referred
                  unknown: 1          0          0          0          0          0
--------------------------------------------------
Summary Statistics
--------------------------------------------------
process
                  signals: 1
--------------------------------------------------
timing
                  runtime: 00:00:25
                  seconds: 25.182182
                 pkts/sec: 1
o")~   Snort exiting

```

### **Snort Rules**

Snort rules, kinda like Suricata rules.

You can studying Snort rule writing from the following resources: [https://docs.snort.org/](https://docs.snort.org/), [https://docs.suricata.io/en/latest/rules/differences-from-snort.html](https://docs.suricata.io/en/latest/rules/differences-from-snort.html).

Just like in Suricata, you need to specify in the configuration file which rule file Snort should use, for example:

```bash
ips =
{
    { variables = default_variables,
      include = '/home/htb-student/local.rules'
    }
}
```

Here, `include = '/home/htb-student/local.rules'` means "when Snort starts, load and use this rule file."

- **Use `-R`** followed by a file path if you want to load just **one specific** rules file.
- **Use `-rule-path`** followed by a folder path if you want to load **every** rules file inside that folder at once.

### **Snort Outputs**

#### **#1. Basic Statistics**

When Snort finishes running, it outputs a summary report broken down into four key areas:

- **Packet Statistics:** Details on the raw network packets received and decoded (e.g., total packets, UDP vs. TCP).
- **Module Statistics:** Activity counters (peg counts) that track specific actions performed by Snort's internal modules (e.g., processed HTTP requests).
- **File Statistics:** A breakdown of analyzed files by type, size in bytes, and matching signatures.
- **Summary Statistics:** Overall performance metrics, including total runtime and processing speed (packets per second).

#### **#2. Alert Outputs**

To actually see detection events triggered by your rules, you must explicitly enable alerting using the `-A` flag. Snort supports multiple alert formats depending on your needs:

- **`-A cmg`**: Displays the alert alongside the raw packet headers and the actual payload (as seen in the command line examples provided).
- **`-A u2` (unified2)**: Logs events in a binary format intended for later analysis by other security tools.
- **`-A csv`**: Outputs alerts in a comma-separated format, which is highly customizable and easy to parse.

#### **#3. Performance Monitoring**

For deeper system tuning, Snort offers extra modules:

- **`perf_monitor`**: Captures real-time performance data without stopping Snort, which can be sent to external monitoring tools.
- **`profiler`**: Tracks how much time and memory specific rules and modules are consuming, helping you optimize Snort's performance.

## Snort Rule Development

### **Snort Rule Development Example 1: Detecting Ursnif (Inefficiently)**

```bash
alert tcp any any -> any any (msg:"Possible Ursnif C2 Activity"; flow:established,to_server; content:"/images/", depth 12; content:"_2F"; content:"_2B"; content:"User-Agent|3a 20|Mozilla/4.0 (compatible|3b| MSIE 8.0|3b| Windows NT"; content:!"Accept"; content:!"Cookie|3a|"; content:!"Referer|3a|"; sid:1000002; rev:1;)
```

The Snort rule above is designed to detect certain variations of [Ursnif](https://www.fortinet.com/blog/threat-research/ursnif-variant-spreading-word-document) malware. The rule is inefficient since it misses HTTP sticky buffers.

```jsx
**$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/ursnif.pcap -A cmg**
--------------------------------------------------
o")~   Snort++ 3.1.64.0
--------------------------------------------------
Loading /root/snorty/etc/snort/snort.lua:
Loading snort_defaults.lua:
Finished snort_defaults.lua:
        hosts
---SNIP---
        host_tracker
Finished /root/snorty/etc/snort/snort.lua:
Loading file_id.rules_file:
Loading file_magic.rules:
Finished file_magic.rules:
Finished file_id.rules_file:
Loading /home/htb-student/local.rules:
Finished /home/htb-student/local.rules:
Loading rule args:
Loading /home/htb-student/local.rules:
Finished /home/htb-student/local.rules:
Finished rule args:
--------------------------------------------------
ips policies rule stats
              id  loaded  shared enabled    file
               0     210       2     210    /root/snorty/etc/snort/snort.lua
--------------------------------------------------
rule counts
       total rules loaded: 210
          duplicate rules: 2
               text rules: 210
            option chains: 210
            chain headers: 5
--------------------------------------------------
port rule counts
             tcp     udp    icmp      ip
     any       1       0       1       0
   total       1       0       1       0
--------------------------------------------------
service rule counts          to-srv  to-cli
                  file_id:      208     208
                    total:      208     208
--------------------------------------------------
fast pattern groups
                      any: 2
                to_server: 1
                to_client: 1
--------------------------------------------------
search engine (ac_bnfa)
                instances: 3
                 patterns: 417
            pattern chars: 2566
               num states: 1836
         num match states: 371
             memory scale: KB
             total memory: 70.9639
           pattern memory: 18.792
        match list memory: 27.8125
        transition memory: 23.9844
appid: MaxRss diff: 3024
appid: patterns loaded: 300
--------------------------------------------------
**pcap DAQ configured to read-file.
Commencing packet processing
++ [0] /home/htb-student/pcaps/ursnif.pcap
07/21-19:27:47.161230 [**] [1:1000002:1] "Possible Ursnif C2 Activity" [**] [Priority: 0] {TCP} 10.10.10.104:49191 -> 192.42.116.41:80
00:1F:E2:10:8B:C9 -> 00:0C:29:C9:67:00 type:0x800 len:0x18C
10.10.10.104:49191 -> 192.42.116.41:80 TCP TTL:128 TOS:0x0 ID:20640 IpLen:20 DgmLen:382 DF
***AP*** Seq: 0x12E06BB  Ack: 0xE061E225  Win: 0x4029  TcpLen: 20

snort.raw[342]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
47 45 54 20 2F 69 6D 61  67 65 73 2F 70 32 52 55  GET /ima ges/p2RU
52 68 5F 32 2F 42 6B 32  76 72 31 4F 59 52 46 31  Rh_2/Bk2 vr1OYRF1
57 47 75 35 6E 67 5F 32  46 73 66 73 2F 57 4F 57  WGu5ng_2 Fsfs/WOW
72 47 54 45 54 79 4B 2F  37 4D 7A 4D 5F 32 42 6E  rGTETyK/ 7MzM_2Bn
47 5A 51 52 32 6A 73 67  50 2F 73 5F 32 42 70 53  GZQR2jsg P/s_2BpS
34 31 4B 37 41 67 2F 4F  75 4A 6A 51 66 41 61 63  41K7Ag/O uJjQfAac
32 64 2F 76 6D 46 5F 32  46 31 4B 42 50 72 4B 5F  2d/vmF_2 F1KBPrK_
32 2F 46 36 36 38 32 64  67 64 69 61 47 31 7A 75  2/F6682d gdiaG1zu
56 43 7A 37 47 68 64 2F  62 4C 37 36 57 66 35 71  VCz7Ghd/ bL76Wf5q
64 71 77 56 35 76 7A 52  2F 32 65 31 41 38 79 42  dqwV5vzR /2e1A8yB
49 64 6B 6D 49 5F 32 42  2F 6F 67 79 7A 4E 55 57  IdkmI_2B /ogyzNUW
33 47 72 2F 67 4B 42 5A  57 58 78 2E 67 69 66 20  3Gr/gKBZ WXx.gif
48 54 54 50 2F 31 2E 31  0D 0A 55 73 65 72 2D 41  HTTP/1.1 ..User-A
67 65 6E 74 3A 20 4D 6F  7A 69 6C 6C 61 2F 34 2E  gent: Mo zilla/4.
30 20 28 63 6F 6D 70 61  74 69 62 6C 65 3B 20 4D  0 (compa tible; M
53 49 45 20 38 2E 30 3B  20 57 69 6E 64 6F 77 73  SIE 8.0;  Windows
20 4E 54 20 36 2E 31 29  0D 0A 48 6F 73 74 3A 20   NT 6.1) ..Host:
62 6C 75 65 77 61 74 65  72 73 74 6F 6E 65 2E 72  bluewate rstone.r
75 0D 0A 43 6F 6E 6E 65  63 74 69 6F 6E 3A 20 4B  u..Conne ction: K
65 65 70 2D 41 6C 69 76  65 0D 0A 43 61 63 68 65  eep-Aliv e..Cache
2D 43 6F 6E 74 72 6F 6C  3A 20 6E 6F 2D 63 61 63  -Control : no-cac
68 65 0D 0A 0D 0A                                 he....
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

-- [0] /home/htb-student/pcaps/ursnif.pcap**
--------------------------------------------------
Packet Statistics
--------------------------------------------------
daq
                    pcaps: 1
                 received: 49
                 analyzed: 49
                    allow: 49
                 rx_bytes: 5925
--------------------------------------------------
codec
                    total: 49           (100.000%)
                      eth: 49           (100.000%)
                     ipv4: 49           (100.000%)
                      tcp: 16           ( 32.653%)
                      udp: 33           ( 67.347%)
--------------------------------------------------
Module Statistics
--------------------------------------------------
appid
                  packets: 49
        processed_packets: 49
           total_sessions: 15
       service_cache_adds: 5
             bytes_in_use: 760
             items_in_use: 5
--------------------------------------------------
back_orifice
                  packets: 33
--------------------------------------------------
binder
                new_flows: 12
          service_changes: 2
                 inspects: 12
--------------------------------------------------
detection
                 analyzed: 49
             raw_searches: 2
          cooked_searches: 1
             pkt_searches: 3
            file_searches: 1
                   alerts: 1
             total_alerts: 1
                   logged: 1
--------------------------------------------------
dns
                  packets: 19
                 requests: 12
                responses: 7
--------------------------------------------------
file_id
              total_files: 1
          total_file_data: 304
     max_concurrent_files: 1
--------------------------------------------------
http_inspect
                    flows: 2
                    scans: 9
              reassembles: 9
              inspections: 9
                 requests: 2
                responses: 2
             get_requests: 1
            post_requests: 1
           request_bodies: 1
  max_concurrent_sessions: 2
              total_bytes: 1603
--------------------------------------------------
port_scan
                  packets: 49
                 trackers: 7
--------------------------------------------------
search_engine
               max_queued: 1
            total_flushed: 2
            total_inserts: 2
             total_unique: 2
     non_qualified_events: 1
         qualified_events: 1
           searched_bytes: 2192
--------------------------------------------------
stream
                    flows: 12
             total_prunes: 7
idle_prunes_proto_timeout: 7
--------------------------------------------------
stream_tcp
                 sessions: 2
                      max: 2
                  created: 2
                 released: 2
             instantiated: 2
                   setups: 2
                 restarts: 2
             syn_trackers: 2
              segs_queued: 4
            segs_released: 4
                segs_used: 4
          rebuilt_packets: 9
            rebuilt_bytes: 1627
                     syns: 2
                 syn_acks: 2
                   resets: 2
                 max_segs: 1
                max_bytes: 981
--------------------------------------------------
stream_udp
                 sessions: 10
                      max: 10
                  created: 13
                 released: 13
                 timeouts: 3
              total_bytes: 1964
--------------------------------------------------
wizard
                tcp_scans: 2
                 tcp_hits: 2
                udp_scans: 3
               udp_misses: 3
--------------------------------------------------
Appid Statistics
--------------------------------------------------
detected apps and services
              Application: Services   Clients    Users      Payloads   Misc       Referred
                  unknown: 11         9          0          2          0          0
--------------------------------------------------
Summary Statistics
--------------------------------------------------
timing
                  runtime: 00:00:00
                  seconds: 0.039200
                 pkts/sec: 1250
                Mbits/sec: 1
o")~   Snort exiting
```

### **Snort Rule Development Example 2: Detecting Cerber**

```jsx
alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible Cerber Check-in"; dsize:9; content:"hi", depth 2, fast_pattern; pcre:"/^[af0-9]{7}$/R"; detection_filter:track by_src, count 1, seconds 60; sid:2816763; rev:4;)
```

The Snort rule above is designed to detect certain variations of [Cerber](https://blog.checkpoint.com/research/14959/) malware. 

```jsx
**$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/cerber.pcap -A cmg**
--------------------------------------------------
o")~   Snort++ 3.1.64.0
--------------------------------------------------
Loading /root/snorty/etc/snort/snort.lua:
Loading snort_defaults.lua:
Finished snort_defaults.lua:
        output
---SNIP---
        trace
Finished /root/snorty/etc/snort/snort.lua:
Loading file_id.rules_file:
Loading file_magic.rules:
Finished file_magic.rules:
Finished file_id.rules_file:
Loading /home/htb-student/local.rules:
Finished /home/htb-student/local.rules:
Loading rule args:
Loading /home/htb-student/local.rules:
Finished /home/htb-student/local.rules:
Finished rule args:
--------------------------------------------------
ips policies rule stats
              id  loaded  shared enabled    file
               0     210       2     210    /root/snorty/etc/snort/snort.lua
--------------------------------------------------
rule counts
       total rules loaded: 210
          duplicate rules: 2
               text rules: 210
            option chains: 210
            chain headers: 5
--------------------------------------------------
port rule counts
             tcp     udp    icmp      ip
     any       0       1       1       0
   total       0       1       1       0
--------------------------------------------------
service rule counts          to-srv  to-cli
                  file_id:      208     208
                    total:      208     208
--------------------------------------------------
fast pattern groups
                      any: 2
                to_server: 1
                to_client: 1
--------------------------------------------------
search engine (ac_bnfa)
                instances: 3
                 patterns: 417
            pattern chars: 2511
               num states: 1781
         num match states: 371
             memory scale: KB
             total memory: 69.8359
           pattern memory: 18.7383
        match list memory: 27.3828
        transition memory: 23.3398
appid: MaxRss diff: 3024
appid: patterns loaded: 300
--------------------------------------------------
pcap DAQ configured to read-file.
Commencing packet processing
++ [0] /home/htb-student/pcaps/cerber.pcap
07/22-02:17:56.486663 [**] [1:2816763:4] "Possible Cerber Check-in" [**] [Priority: 0] {UDP} 10.0.2.15:1046 -> 31.184.234.1:6892
08:00:27:A9:8C:97 -> 52:54:00:12:35:02 type:0x800 len:0x3C
10.0.2.15:1046 -> 31.184.234.1:6892 UDP TTL:128 TOS:0x0 ID:83 IpLen:20 DgmLen:37
Len: 9

snort.raw[9]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
68 69 30 30 37 32 38 39  35                       hi007289 5
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

07/22-02:17:56.486795 [**] [1:2816763:4] "Possible Cerber Check-in" [**] [Priority: 0] {UDP} 10.0.2.15:1046 -> 31.184.234.2:6892
08:00:27:A9:8C:97 -> 52:54:00:12:35:02 type:0x800 len:0x3C
10.0.2.15:1046 -> 31.184.234.2:6892 UDP TTL:128 TOS:0x0 ID:84 IpLen:20 DgmLen:37
Len: 9

snort.raw[9]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
68 69 30 30 37 32 38 39  35                       hi007289 5
---SNIP---
-- [0] /home/htb-student/pcaps/cerber.pcap
--------------------------------------------------
Packet Statistics
--------------------------------------------------
daq
                    pcaps: 1
                 received: 1035
                 analyzed: 1035
                    allow: 1035
                 rx_bytes: 65672
--------------------------------------------------
codec
                    total: 1035         (100.000%)
                      eth: 1035         (100.000%)
                     ipv4: 1035         (100.000%)
                      tcp: 9            (  0.870%)
                      udp: 1026         ( 99.130%)
--------------------------------------------------
Module Statistics
--------------------------------------------------
appid
                  packets: 1035
        processed_packets: 1035
           total_sessions: 1026
       service_cache_adds: 514
             bytes_in_use: 78128
             items_in_use: 514
--------------------------------------------------
back_orifice
                  packets: 514
--------------------------------------------------
binder
                new_flows: 1026
          service_changes: 1
                 inspects: 1026
--------------------------------------------------
detection
                 analyzed: 1035
             raw_searches: 1026
             pkt_searches: 1026
            file_searches: 1
                   alerts: 511
             total_alerts: 511
                   logged: 511
--------------------------------------------------
dns
                  packets: 2
                 requests: 1
                responses: 1
--------------------------------------------------
file_id
              total_files: 1
          total_file_data: 164
     max_concurrent_files: 1
--------------------------------------------------
http_inspect
                    flows: 1
                    scans: 5
              reassembles: 5
              inspections: 5
                 requests: 1
                responses: 1
             get_requests: 1
  max_concurrent_sessions: 1
              total_bytes: 462
--------------------------------------------------
pcre
               pcre_rules: 2
              pcre_native: 2
--------------------------------------------------
port_scan
                  packets: 1035
                 trackers: 516
--------------------------------------------------
search_engine
               max_queued: 1
            total_flushed: 512
            total_inserts: 512
             total_unique: 512
     non_qualified_events: 1
         qualified_events: 511
           searched_bytes: 17146
--------------------------------------------------
stream
                    flows: 1026
--------------------------------------------------
stream_tcp
                 sessions: 1
                      max: 1
                  created: 1
                 released: 1
             instantiated: 1
                   setups: 1
                 restarts: 1
             syn_trackers: 1
              segs_queued: 2
            segs_released: 2
                segs_used: 2
          rebuilt_packets: 5
            rebuilt_bytes: 474
                     syns: 1
                 syn_acks: 1
                     fins: 1
                 max_segs: 1
                max_bytes: 435
--------------------------------------------------
stream_udp
                 sessions: 1025
                      max: 1025
                  created: 1025
                 released: 1025
              total_bytes: 16982
--------------------------------------------------
wizard
                tcp_scans: 1
                 tcp_hits: 1
                udp_scans: 1024
               udp_misses: 1024
--------------------------------------------------
Appid Statistics
--------------------------------------------------
detected apps and services
              Application: Services   Clients    Users      Payloads   Misc       Referred
                  unknown: 2          1          0          1          0          0
--------------------------------------------------
Summary Statistics
--------------------------------------------------
timing
                  runtime: 00:01:11
                  seconds: 71.153373
                 pkts/sec: 15
o")~   Snort exiting
```

### **Snort Rule Development Example 3: Detecting Patchwork**

```jsx
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"OISF TROJAN Targeted AutoIt FileStealer/Downloader CnC Beacon"; flow:established,to_server; http_method; content:"POST"; http_uri; content:".php?profile="; http_client_body; content:"ddager=", depth 7; http_client_body; content:"&r1=", distance 0; http_header; content:!"Accept"; http_header; content:!"Referer|3a|"; sid:10000006; rev:1;)
```

The Snort rule above is designed to detect certain variations of malware used by the [Patchwork](https://paper.seebug.org/papers/APT/APT_CyberCriminal_Campagin/2016/2016.07.07.UNVEILING_PATCHWORK/Unveiling-Patchwork.pdf) APT. 

```bash
**$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/patchwork.pcap -A cmg**
--------------------------------------------------
o")~   Snort++ 3.1.64.0
--------------------------------------------------
Loading /root/snorty/etc/snort/snort.lua:
Loading snort_defaults.lua:
Finished snort_defaults.lua:
        output
---SNIP--- 
        trace
Finished /root/snorty/etc/snort/snort.lua:
Loading file_id.rules_file:
Loading file_magic.rules:
Finished file_magic.rules:
Finished file_id.rules_file:
Loading /home/htb-student/local.rules:
Finished /home/htb-student/local.rules:
Loading rule args:
Loading /home/htb-student/local.rules:
Finished /home/htb-student/local.rules:
Finished rule args:
--------------------------------------------------
ips policies rule stats
              id  loaded  shared enabled    file
               0     210       2     210    /root/snorty/etc/snort/snort.lua
--------------------------------------------------
rule counts
       total rules loaded: 210
          duplicate rules: 2
               text rules: 210
            option chains: 210
            chain headers: 5
--------------------------------------------------
port rule counts
             tcp     udp    icmp      ip
     any       0       0       1       0
   total       0       0       1       0
--------------------------------------------------
service rule counts          to-srv  to-cli
                  file_id:      208     208
                     http:        1       0
                    http2:        1       0
                    http3:        1       0
                    total:      211     208
--------------------------------------------------
fast pattern groups
                to_server: 4
                to_client: 1
--------------------------------------------------
search engine (ac_bnfa)
                instances: 5
                 patterns: 419
            pattern chars: 2550
               num states: 1820
         num match states: 373
             memory scale: KB
             total memory: 73.0088
           pattern memory: 18.8525
        match list memory: 27.75
        transition memory: 25.7812
appid: MaxRss diff: 2964
appid: patterns loaded: 300
--------------------------------------------------
**pcap DAQ configured to read-file.
Commencing packet processing
++ [0] /home/htb-student/pcaps/patchwork.pcap
06/01-19:24:43.339294 [**] [1:10000006:1] "OISF TROJAN Targeted AutoIt FileStealer/Downloader CnC Beacon" [**] [Priority: 0] {TCP} 192.168.1.37:49176 -> 212.129.13.110:8
0

http_inspect.http_method[4]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
50 4F 53 54                                       POST
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

http_inspect.http_version[8]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
48 54 54 50 2F 31 2E 31                           HTTP/1.1
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

http_inspect.http_uri[37]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
2F 64 72 6F 70 70 65 72  2E 70 68 70 3F 70 72 6F  /dropper .php?pro
66 69 6C 65 3D 63 6D 56  6B 63 30 42 43 55 45 46  file=cmV kc0BCUEF
4A 54 67 3D 3D                                    JTg==
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

http_inspect.http_header[167]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
43 6F 6E 6E 65 63 74 69  6F 6E 3A 20 4B 65 65 70  Connecti on: Keep
2D 41 6C 69 76 65 0D 0A  43 6F 6E 74 65 6E 74 2D  -Alive.. Content-
54 79 70 65 3A 20 61 70  70 6C 69 63 61 74 69 6F  Type: ap plicatio
6E 2F 78 2D 77 77 77 2D  66 6F 72 6D 2D 75 72 6C  n/x-www- form-url
65 6E 63 6F 64 65 64 0D  0A 55 73 65 72 2D 41 67  encoded. .User-Ag
65 6E 74 3A 20 4D 6F 7A  69 6C 6C 61 2F 35 2E 30  ent: Moz illa/5.0
20 46 69 72 65 66 6F 78  20 28 4C 69 6B 65 20 53   Firefox  (Like S
61 66 61 72 69 2F 57 65  62 6B 69 74 29 0D 0A 43  afari/We bkit)..C
6F 6E 74 65 6E 74 2D 4C  65 6E 67 74 68 3A 20 36  ontent-L ength: 6
34 0D 0A 48 6F 73 74 3A  20 32 31 32 2E 31 32 39  4..Host:  212.129
2E 31 33 2E 31 31 30                             .13.110
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

http_inspect.http_client_body[64]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
64 64 61 67 65 72 3D 30  26 72 31 3D 56 30 6C 4F  ddager=0 &r1=V0lO
58 7A 63 3D 26 72 32 3D  57 44 59 30 26 72 33 3D  Xzc=&r2= WDY0&r3=
4D 53 34 78 26 72 34 3D  4D 41 3D 3D 26 72 35 3D  MS4x&r4= MA==&r5=
49 43 41 3D 26 72 36 3D  56 48 4A 31 5A 51 3D 3D  ICA=&r6= VHJ1ZQ==
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

06/01-19:25:09.059391 [**] [1:10000006:1] "OISF TROJAN Targeted AutoIt FileStealer/Downloader CnC Beacon" [**] [Priority: 0] {TCP} 192.168.1.37:49186 -> 212.129.13.110:8
0
---SNIP---
-- [0] /home/htb-student/pcaps/patchwork.pcap**
--------------------------------------------------
Packet Statistics
--------------------------------------------------
daq
                    pcaps: 1
                 received: 4868
                 analyzed: 4868
                    allow: 4155
                whitelist: 713
                 rx_bytes: 3561155
--------------------------------------------------
codec
                    total: 4868         (100.000%)
                 discards: 1            (  0.021%)
                      eth: 4868         (100.000%)
                     ipv4: 4868         (100.000%)
                      tcp: 4834         ( 99.302%)
                      udp: 33           (  0.678%)
--------------------------------------------------
Module Statistics
--------------------------------------------------
appid
                  packets: 4867
        processed_packets: 4867
           total_sessions: 11
       service_cache_adds: 6
             bytes_in_use: 912
             items_in_use: 6
--------------------------------------------------
back_orifice
                  packets: 33
--------------------------------------------------
binder
              raw_packets: 1
                new_flows: 10
          service_changes: 7
                 inspects: 11
--------------------------------------------------
dce_smb
                 sessions: 1
                  packets: 17
            ignored_bytes: 287
 max_outstanding_requests: 1
  max_concurrent_sessions: 1
      total_smb1_sessions: 1
--------------------------------------------------
detection
                 analyzed: 4868
             pdu_searches: 257
            file_searches: 514
                   alerts: 257
             total_alerts: 257
                   logged: 257
--------------------------------------------------
file_id
              total_files: 514
          total_file_data: 390466
     max_concurrent_files: 1
--------------------------------------------------
http_inspect
                    flows: 4
                    scans: 2822
              reassembles: 2822
              inspections: 1542
                 requests: 257
                responses: 257
            post_requests: 257
           request_bodies: 257
  max_concurrent_sessions: 1
              total_bytes: 2081981
--------------------------------------------------
normalizer
        test_tcp_trim_win: 8
--------------------------------------------------
port_scan
                  packets: 4867
                 trackers: 8
--------------------------------------------------
search_engine
               max_queued: 1
            total_flushed: 513
            total_inserts: 513
             total_unique: 513
     non_qualified_events: 256
         qualified_events: 257
           searched_bytes: 399719
--------------------------------------------------
ssl
                  packets: 71
                  decoded: 71
             client_hello: 2
             server_hello: 2
              certificate: 2
              server_done: 6
      client_key_exchange: 2
            change_cipher: 4
       client_application: 3
       server_application: 56
                    alert: 1
     unrecognized_records: 6
     handshakes_completed: 1
         sessions_ignored: 1
  max_concurrent_sessions: 1
--------------------------------------------------
stream
                    flows: 10
             total_prunes: 3
idle_prunes_proto_timeout: 3
--------------------------------------------------
stream_tcp
                 sessions: 7
                      max: 7
                  created: 7
                 released: 7
             instantiated: 7
                   setups: 7
                 restarts: 7
          invalid_seq_num: 8
             syn_trackers: 7
              segs_queued: 2735
            segs_released: 2735
                segs_used: 2734
          rebuilt_packets: 1631
            rebuilt_bytes: 2981239
                     gaps: 6
                     syns: 8
                 syn_acks: 7
                   resets: 1
                     fins: 10
                 max_segs: 15
                max_bytes: 20520
--------------------------------------------------
stream_udp
                 sessions: 3
                      max: 3
                  created: 4
                 released: 4
                 timeouts: 1
              total_bytes: 2359
--------------------------------------------------
wizard
                tcp_scans: 9
                 tcp_hits: 7
                udp_scans: 3
               udp_misses: 3
--------------------------------------------------
Appid Statistics
--------------------------------------------------
detected apps and services
              Application: Services   Clients    Users      Payloads   Misc       Referred
                  unknown: 9          4          0          6          0          0
--------------------------------------------------
Summary Statistics
--------------------------------------------------
timing
                  runtime: 00:01:21
                  seconds: 81.152785
                 pkts/sec: 60
o")~   Snort exiting
```

### **Snort Rule Development Example 4: Detecting Patchwork (SSL)**

```jsx
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Patchwork SSL Cert Detected"; flow:established,from_server; content:"|55 04 03|"; content:"|08|toigetgf", distance 1, within 9; classtype:trojan-activity; sid:10000008; rev:1;)
```

The Snort rule above is designed to detect certain variations of malware used by the Patchwork APT

```bash
**$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/patchwork.pcap -A cmg**

--------------------------------------------------
o")~   Snort++ 3.1.64.0
--------------------------------------------------
Loading /root/snorty/etc/snort/snort.lua:
Loading snort_defaults.lua:
Finished snort_defaults.lua:
        ips
--SNIP---
        trace
        active
Finished /root/snorty/etc/snort/snort.lua:
Loading file_id.rules_file:
Loading file_magic.rules:
Finished file_magic.rules:
Finished file_id.rules_file:
Loading /home/htb-student/local.rules:
Finished /home/htb-student/local.rules:
Loading rule args:
Loading /home/htb-student/local.rules:
Finished /home/htb-student/local.rules:
Finished rule args:
--------------------------------------------------
ips policies rule stats
              id  loaded  shared enabled    file
               0     210       2     210    /root/snorty/etc/snort/snort.lua
--------------------------------------------------
rule counts
       total rules loaded: 210
          duplicate rules: 2
               text rules: 210
            option chains: 210
            chain headers: 5
--------------------------------------------------
port rule counts
             tcp     udp    icmp      ip
     any       1       0       1       0
   total       1       0       1       0
--------------------------------------------------
service rule counts          to-srv  to-cli
                  file_id:      208     208
                    total:      208     208
--------------------------------------------------
fast pattern groups
                      any: 2
                to_server: 1
                to_client: 1
--------------------------------------------------
search engine (ac_bnfa)
                instances: 3
                 patterns: 417
            pattern chars: 2518
               num states: 1788
         num match states: 371
             memory scale: KB
             total memory: 69.9795
           pattern memory: 18.7451
        match list memory: 27.4375
        transition memory: 23.4219
appid: MaxRss diff: 3084
appid: patterns loaded: 300
--------------------------------------------------
**pcap DAQ configured to read-file.
Commencing packet processing
++ [0] /home/htb-student/pcaps/patchwork.pcap
06/01-19:25:29.876240 [**] [1:10000008:1] "Patchwork SSL Cert Detected" [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 45.43.192.172:8443 -> 192.168.1.37:49211

ssl.stream_tcp[807]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
16 03 03 00 51 02 00 00  4D 03 03 74 19 1E 0B 50  ....Q... M..t...P
F2 80 7F 3F 81 1C 07 CF  58 0B A0 48 B0 F7 A7 D4  ...?.... X..H....
8B 08 53 2D 10 62 F9 23  F0 CD 76 20 A3 17 4D A2  ..S-.b.# ..v ..M.
35 58 EC 8B 4A F2 74 6D  72 7F CC 80 45 E8 1E 73  5X..J.tm r...E..s
2E 22 18 99 75 FB D1 FF  0E 97 C8 04 00 3C 00 00  ."..u... .....<..
05 FF 01 00 01 00 16 03  03 02 C3 0B 00 02 BF 00  ........ ........
02 BC 00 02 B9 30 82 02  B5 30 82 01 9D A0 03 02  .....0.. .0......
01 02 02 08 44 0E 87 29  65 41 6D 2A 30 0D 06 09  ....D..) eAm*0...
2A 86 48 86 F7 0D 01 01  0B 05 00 30 13 31 11 30  *.H..... ...0.1.0
0F 06 03 55 04 03 0C 08  74 6F 69 67 65 74 67 66  ...U.... toigetgf
30 1E 17 0D 31 34 31 31  31 38 30 36 30 38 33 38  0...1411 18060838
5A 17 0D 32 34 31 31 31  35 30 36 30 38 33 38 5A  Z..24111 5060838Z
30 13 31 11 30 0F 06 03  55 04 03 0C 08 74 6F 69  0.1.0... U....toi
67 65 74 67 66 30 82 01  22 30 0D 06 09 2A 86 48  getgf0.. "0...*.H
86 F7 0D 01 01 01 05 00  03 82 01 0F 00 30 82 01  ........ .....0..
0A 02 82 01 01 00 C6 B9  1B 97 5C 6E DA 23 4C 02  ........ ..\n.#L.
EC A6 A8 09 56 FA 85 5E  35 75 A8 BB 63 B5 81 30  ....V..^ 5u..c..0
90 91 45 D7 19 36 0B 20  DF 70 37 0E 91 05 FB 86  ..E..6.  .p7.....
22 E8 56 3D A5 89 BA 13  01 60 DF 43 A6 F0 05 7B  ".V=.... .`.C...{
5A 04 7F 53 14 80 C1 64  EA 9C 09 98 A2 B8 99 EA  Z..S...d ........
91 26 52 81 62 D3 BB CE  A2 4E E7 BB 97 C9 19 D2  .&R.b... .N......
EF 61 8A A5 50 9A D7 6B  9F 9D 54 7B AE E2 6F 53  .a..P..k ..T{..oS
BB 7A B4 D2 93 06 73 96  CD 04 19 55 D3 7A DA 34  .z....s. ...U.z.4
8F 05 2D 2E 98 7F 6C 9E  0B C8 41 A2 49 BA FB CC  ..-...l. ..A.I...
A4 20 BD 8A E5 18 27 88  BB 87 F9 F6 F3 56 8F 73  . ....'. .....V.s
D6 BA 92 29 F9 F0 A6 AB  F5 FD 5F E0 92 C6 96 2D  ...).... .._....-
41 80 FA 0B 4C C9 9B AE  2D 69 F7 9D B5 4B 14 81  A...L... -i...K..
AD F8 71 6F 2B A8 59 66  6E FD B5 8B 3B 14 09 F7  ..qo+.Yf n...;...
B8 FC 20 EF 7D A0 D5 40  D6 66 BB 65 B6 FC 92 3A  .. .}..@ .f.e...:
71 F5 BA 5B F1 07 A5 FD  E3 11 F2 A9 51 6C 16 8F  q..[.... ....Ql..
C8 72 B7 A0 D7 26 43 3A  18 7B F8 7B 38 72 01 37  .r...&C: .{.{8r.7
4F 42 28 42 2F 01 02 03  01 00 01 A3 0D 30 0B 30  OB(B/... .....0.0
09 06 03 55 1D 13 04 02  30 00 30 0D 06 09 2A 86  ...U.... 0.0...*.
48 86 F7 0D 01 01 0B 05  00 03 82 01 01 00 2D 0E  H....... ......-.
CC D5 50 AB DF 20 37 BB  71 10 31 C5 1F 17 EC F9  ..P.. 7. q.1.....
D7 20 1A 19 39 F4 DE D8  BA C1 A3 F5 57 E0 E0 6B  . ..9... ....W..k
DC 6F E1 1F 6B 07 98 FB  38 1A 0A 77 BD B4 0A 94  .o..k... 8..w....
01 45 95 0C 09 F1 43 D5  7D 57 E7 D6 E7 74 98 6C  .E....C. }W...t.l
4F D0 46 81 F2 9D 5A 29  1E BD 7F 03 5B 64 B3 98  O.F...Z) ....[d..
D4 52 B0 E1 CE 11 62 68  31 1D CC 0F DD B6 AA 5C  .R....bh 1......\
44 D0 44 18 9E 3D AE 30  C7 10 C6 97 F6 C1 C9 D7  D.D..=.0 ........
11 13 44 AA B4 C9 2D 0C  AC 2B AD 9A CB 7B 5D 51  ..D...-. .+...{]Q
3F 45 C6 2E 99 CF 71 F6  66 9A 09 28 44 28 34 3B  ?E....q. f..(D(4;
EC 0B A6 F4 E3 5F FE 7E  30 59 DC 3D 4E 33 22 11  ....._.~ 0Y.=N3".
BA CA 8A 4B 41 5D 97 3E  CD BB 3C DD 28 37 12 47  ...KA].> ..<.(7.G
E0 BE AC 3B 13 EC 59 A0  E3 1A CE 28 B2 11 5D 3B  ...;..Y. ...(..];
AC AD CF 32 F5 EA CB B2  92 20 BC 5C 3C 4C B9 43  ...2.... . .\<L.C
5A BC 1B 2F E3 F3 DF DC  04 DB 24 6A 73 13 EA E5  Z../.... ..$js...
32 45 6A F6 D9 CC 66 9C  80 99 3D EC D9 2D 13 9A  2Ej...f. ..=..-..
9A 6F 90 69 47 95 B6 46  D8 F2 E8 EF CC CA 16 03  .o.iG..F ........
03 00 04 0E 00 00 00                             .......
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

06/01-19:25:44.259156 [**] [1:10000008:1] "Patchwork SSL Cert Detected" [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 45.43.192.172:8443 -> 192.168.1.37:49219

ssl.stream_tcp[807]:
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -
16 03 01 00 51 02 00 00  4D 03 01 BA 21 1C 95 C6  ....Q... M...!...
8A 83 F3 C8 31 16 EF 25  32 C4 63 7E 82 B0 7D D0  ....1..% 2.c~..}.
01 EF 6C 7B DC A3 CD 53  97 18 62 20 C6 FE 9D B0  ..l{...S ..b ....
B0 F4 9B 9A 6E 1D 6B 74  64 4D E4 CC 30 2E 05 B8  ....n.kt dM..0...
30 1A 34 D0 30 94 5B FA  AB 64 27 09 00 2F 00 00  0.4.0.[. .d'../..
05 FF 01 00 01 00 16 03  01 02 C3 0B 00 02 BF 00  ........ ........
02 BC 00 02 B9 30 82 02  B5 30 82 01 9D A0 03 02  .....0.. .0......
01 02 02 08 44 0E 87 29  65 41 6D 2A 30 0D 06 09  ....D..) eAm*0...
2A 86 48 86 F7 0D 01 01  0B 05 00 30 13 31 11 30  *.H..... ...0.1.0
0F 06 03 55 04 03 0C 08  74 6F 69 67 65 74 67 66  ...U.... toigetgf
30 1E 17 0D 31 34 31 31  31 38 30 36 30 38 33 38  0...1411 18060838
5A 17 0D 32 34 31 31 31  35 30 36 30 38 33 38 5A  Z..24111 5060838Z
30 13 31 11 30 0F 06 03  55 04 03 0C 08 74 6F 69  0.1.0... U....toi
67 65 74 67 66 30 82 01  22 30 0D 06 09 2A 86 48  getgf0.. "0...*.H
86 F7 0D 01 01 01 05 00  03 82 01 0F 00 30 82 01  ........ .....0..
0A 02 82 01 01 00 C6 B9  1B 97 5C 6E DA 23 4C 02  ........ ..\n.#L.
EC A6 A8 09 56 FA 85 5E  35 75 A8 BB 63 B5 81 30  ....V..^ 5u..c..0
90 91 45 D7 19 36 0B 20  DF 70 37 0E 91 05 FB 86  ..E..6.  .p7.....
22 E8 56 3D A5 89 BA 13  01 60 DF 43 A6 F0 05 7B  ".V=.... .`.C...{
5A 04 7F 53 14 80 C1 64  EA 9C 09 98 A2 B8 99 EA  Z..S...d ........
91 26 52 81 62 D3 BB CE  A2 4E E7 BB 97 C9 19 D2  .&R.b... .N......
EF 61 8A A5 50 9A D7 6B  9F 9D 54 7B AE E2 6F 53  .a..P..k ..T{..oS
BB 7A B4 D2 93 06 73 96  CD 04 19 55 D3 7A DA 34  .z....s. ...U.z.4
8F 05 2D 2E 98 7F 6C 9E  0B C8 41 A2 49 BA FB CC  ..-...l. ..A.I...
A4 20 BD 8A E5 18 27 88  BB 87 F9 F6 F3 56 8F 73  . ....'. .....V.s
D6 BA 92 29 F9 F0 A6 AB  F5 FD 5F E0 92 C6 96 2D  ...).... .._....-
41 80 FA 0B 4C C9 9B AE  2D 69 F7 9D B5 4B 14 81  A...L... -i...K..
AD F8 71 6F 2B A8 59 66  6E FD B5 8B 3B 14 09 F7  ..qo+.Yf n...;...
B8 FC 20 EF 7D A0 D5 40  D6 66 BB 65 B6 FC 92 3A  .. .}..@ .f.e...:
71 F5 BA 5B F1 07 A5 FD  E3 11 F2 A9 51 6C 16 8F  q..[.... ....Ql..
C8 72 B7 A0 D7 26 43 3A  18 7B F8 7B 38 72 01 37  .r...&C: .{.{8r.7
4F 42 28 42 2F 01 02 03  01 00 01 A3 0D 30 0B 30  OB(B/... .....0.0
09 06 03 55 1D 13 04 02  30 00 30 0D 06 09 2A 86  ...U.... 0.0...*.
48 86 F7 0D 01 01 0B 05  00 03 82 01 01 00 2D 0E  H....... ......-.
CC D5 50 AB DF 20 37 BB  71 10 31 C5 1F 17 EC F9  ..P.. 7. q.1.....
D7 20 1A 19 39 F4 DE D8  BA C1 A3 F5 57 E0 E0 6B  . ..9... ....W..k
DC 6F E1 1F 6B 07 98 FB  38 1A 0A 77 BD B4 0A 94  .o..k... 8..w....
01 45 95 0C 09 F1 43 D5  7D 57 E7 D6 E7 74 98 6C  .E....C. }W...t.l
4F D0 46 81 F2 9D 5A 29  1E BD 7F 03 5B 64 B3 98  O.F...Z) ....[d..
D4 52 B0 E1 CE 11 62 68  31 1D CC 0F DD B6 AA 5C  .R....bh 1......\
44 D0 44 18 9E 3D AE 30  C7 10 C6 97 F6 C1 C9 D7  D.D..=.0 ........
11 13 44 AA B4 C9 2D 0C  AC 2B AD 9A CB 7B 5D 51  ..D...-. .+...{]Q
3F 45 C6 2E 99 CF 71 F6  66 9A 09 28 44 28 34 3B  ?E....q. f..(D(4;
EC 0B A6 F4 E3 5F FE 7E  30 59 DC 3D 4E 33 22 11  ....._.~ 0Y.=N3".
BA CA 8A 4B 41 5D 97 3E  CD BB 3C DD 28 37 12 47  ...KA].> ..<.(7.G
E0 BE AC 3B 13 EC 59 A0  E3 1A CE 28 B2 11 5D 3B  ...;..Y. ...(..];
AC AD CF 32 F5 EA CB B2  92 20 BC 5C 3C 4C B9 43  ...2.... . .\<L.C
5A BC 1B 2F E3 F3 DF DC  04 DB 24 6A 73 13 EA E5  Z../.... ..$js...
32 45 6A F6 D9 CC 66 9C  80 99 3D EC D9 2D 13 9A  2Ej...f. ..=..-..
9A 6F 90 69 47 95 B6 46  D8 F2 E8 EF CC CA 16 03  .o.iG..F ........
01 00 04 0E 00 00 00                             .......
- - - - - - - - - - - -  - - - - - - - - - - - -  - - - - - - - - -

-- [0] /home/htb-student/pcaps/patchwork.pcap**
--------------------------------------------------
Packet Statistics
--------------------------------------------------
daq
                    pcaps: 1
                 received: 4868
                 analyzed: 4868
                    allow: 4155
                whitelist: 713
                 rx_bytes: 3561155
--------------------------------------------------
codec
                    total: 4868         (100.000%)
                 discards: 1            (  0.021%)
                      eth: 4868         (100.000%)
                     ipv4: 4868         (100.000%)
                      tcp: 4834         ( 99.302%)
                      udp: 33           (  0.678%)
--------------------------------------------------
Module Statistics
--------------------------------------------------
appid
                  packets: 4867
        processed_packets: 4867
           total_sessions: 11
       service_cache_adds: 6
             bytes_in_use: 912
             items_in_use: 6
--------------------------------------------------
back_orifice
                  packets: 33
--------------------------------------------------
binder
              raw_packets: 1
                new_flows: 10
          service_changes: 7
                 inspects: 11
--------------------------------------------------
dce_smb
                 sessions: 1
                  packets: 17
            ignored_bytes: 287
 max_outstanding_requests: 1
  max_concurrent_sessions: 1
      total_smb1_sessions: 1
--------------------------------------------------
detection
                 analyzed: 4868
             raw_searches: 21
          cooked_searches: 619
             pkt_searches: 640
            file_searches: 514
                   alerts: 2
             total_alerts: 2
                   logged: 2
--------------------------------------------------
file_id
              total_files: 514
          total_file_data: 390466
     max_concurrent_files: 1
--------------------------------------------------
http_inspect
                    flows: 4
                    scans: 2822
              reassembles: 2822
              inspections: 1542
                 requests: 257
                responses: 257
            post_requests: 257
           request_bodies: 257
  max_concurrent_sessions: 1
              total_bytes: 2081981
--------------------------------------------------
normalizer
        test_tcp_trim_win: 8
--------------------------------------------------
port_scan
                  packets: 4867
                 trackers: 8
--------------------------------------------------
search_engine
               max_queued: 1
            total_flushed: 258
            total_inserts: 258
             total_unique: 258
     non_qualified_events: 256
         qualified_events: 2
           searched_bytes: 3260955
--------------------------------------------------
ssl
                  packets: 71
                  decoded: 71
             client_hello: 2
             server_hello: 2
              certificate: 2
              server_done: 6
      client_key_exchange: 2
            change_cipher: 4
       client_application: 3
       server_application: 56
                    alert: 1
     unrecognized_records: 6
     handshakes_completed: 1
         sessions_ignored: 1
  max_concurrent_sessions: 1
--------------------------------------------------
stream
                    flows: 10
             total_prunes: 3
idle_prunes_proto_timeout: 3
--------------------------------------------------
stream_tcp
                 sessions: 7
                      max: 7
                  created: 7
                 released: 7
             instantiated: 7
                   setups: 7
                 restarts: 7
          invalid_seq_num: 8
             syn_trackers: 7
              segs_queued: 2735
            segs_released: 2735
                segs_used: 2734
          rebuilt_packets: 1631
            rebuilt_bytes: 2981239
                     gaps: 6
                     syns: 8
                 syn_acks: 7
                   resets: 1
                     fins: 10
                 max_segs: 15
                max_bytes: 20520
--------------------------------------------------
stream_udp
                 sessions: 3
                      max: 3
                  created: 4
                 released: 4
                 timeouts: 1
              total_bytes: 2359
--------------------------------------------------
wizard
                tcp_scans: 9
                 tcp_hits: 7
                udp_scans: 3
               udp_misses: 3
--------------------------------------------------
Appid Statistics
--------------------------------------------------
detected apps and services
              Application: Services   Clients    Users      Payloads   Misc       Referred
                  unknown: 9          4          0          6          0          0
--------------------------------------------------
Summary Statistics
--------------------------------------------------
timing
                  runtime: 00:00:00
                  seconds: 0.078293
                 pkts/sec: 62177
                Mbits/sec: 347
o")~   Snort exiting
```

# Zeek

## **Zeek Fundamentals**

Zeek is an open-source network analysis tool. It is also a tool for troubleshooting network issues and performing measurements. 'Zeek' sounds quite similar to 'Seek'. Initially, this software was named 'Bro'. Zeek uses a Scripting Language instead of the rules used by Suricata and Snort.

## **Zeek's Operation Modes**

Zeek operates in the following modes:

- Fully passive traffic analysis
- libpcap interface for packet capture
- Real-time and offline (e.g., PCAP-based) analysis
- Cluster support for large-scale deployments

## **Zeek's Architecture**

Zeek's architecture consists of two phases.

First, **the core (Event Engine)** is responsible for receiving all raw network data and translating it into objective event reports, merely recording what is happening on the network without making any judgments or evaluations.

These event reports are then automatically queued and forwarded to the second component, the **Script Interpreter**; here, the system automatically applies security rules pre-programmed by administrators (Zeek scripts) to deeply analyze the context, assess the threat level of each event, and make appropriate decisions to alert or block.

Most of Zeek's events are defined in `.bif` files located in the `/scripts/base/bif/plugins/` directory. [[Ref]](https://docs.zeek.org/en/stable/scripts/base/bif/)

## **Zeek Logs**

Among the diverse array of logs Zeek produces, some familiar ones include:

- `conn.log`: This log provides details about IP, TCP, UDP, and ICMP connections.
- `dns.log`: Here, you'll find the details of DNS queries and responses.
- `http.log`: This log captures the details of HTTP requests and responses.
- `ftp.log`: Details of FTP requests and responses are logged here.
- `smtp.log`: This log covers SMTP transactions, such as sender and recipient details.

[[ref]](https://docs.zeek.org/en/master/logs/index.html)

Zeek, in its standard configuration, applies gzip compression to log files every hour. The older logs are then transferred into a directory named in the `YYYY-MM-DD` format. When dealing with these compressed logs, alternative tools like `gzcat` for printing logs or `zgrep` for searching within logs can come in handy.

Zeek also provides a specialized tool known as `zeek-cut` for handling log files.

## Intrusion Detect ith Zeek

### **Intrusion Detection With Zeek Example 1: Detecting Beaconing Malware**

Beaconing is a process by which malware communicates with its command and control (C2) server to receive instructions or exfiltrate data.

By analyzing connection logs (`conn.log`), we can look for patterns in outbound traffic.

```bash
$ /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/psempire.pcap
```

```bash
$ cat conn.log
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   conn
#open   2023-07-16-12-15-40
#fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   service duration        orig_bytes      resp_bytes      conn_state      local_orig      local_resp      missed_bytes    history o_pkts   orig_ip_bytes   resp_pkts       resp_ip_bytes   tunnel_parents
#types  time    string  addr    port    addr    port    enum    string  interval        count   count   string  bool    bool    count   string  count   count   count   count   set[string]
1511269439.125289       CuQYC98rE69BBb7jb       192.168.56.14   50436   51.15.197.127   80      tcp     http    2.186789        204     5557    SF      -       -       0       ShADadfF        5       416     8       5889    -
1511269436.547667       CTc2Qc2kleCjVaU0V1      fe80::ec23:e8b7:91cb:974d       61431   ff02::1:3       5355    udp     dns     0.094916        44      0       S0      -       -       0       D       2       140     0       0
1511269436.548234       Cd4aTbH02m0iB9XS9       192.168.56.14   64755   224.0.0.252     5355    udp     dns     0.094893        44      0       S0      -       -       0       D       2       100     0       0       -
1511269445.266039       CjKEcE3tUWBHhYM93d      192.168.56.14   50437   51.15.197.127   80      tcp     http    0.214611        683     482     SF      -       -       0       ShADadfF        6       935     6       734     -
1511269446.190550       CNah6o4OZz5Sr5wGq1      192.168.56.14   50438   51.15.197.127   80      tcp     http    0.150132        436     39502   SF      -       -       0       ShADadfF        11      888     33      40834   -
1511269451.891317       CA6iaN3UgCDI0Sy9x4      192.168.56.14   50439   51.15.197.127   80      tcp     http    0.098543        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269457.130160       ChcRft1mTccVo2yQfa      192.168.56.14   50440   51.15.197.127   80      tcp     http    0.119445        208     399     SF      -       -       0       ShADadfF        5       420     5       611     -
1511269462.359918       Clja4s40wWlk8bkAW4      192.168.56.14   50441   51.15.197.127   80      tcp     http    0.129297        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269467.593242       CyE3Th1j6AunL5E3Pl      192.168.56.14   50442   51.15.197.127   80      tcp     http    0.181411        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269472.881671       CwuY7B34I442zmY0hf      192.168.56.14   50443   51.15.197.127   80      tcp     http    0.121359        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269478.120597       CVPMlj3atDGkCy1xyk      192.168.56.14   50444   51.15.197.127   80      tcp     http    0.121619        208     399     SF      -       -       0       ShADadfF        5       420     5       611     -
1511269483.366011       Ckn8aZn8c67nuAE19       192.168.56.14   50445   51.15.197.127   80      tcp     http    0.122851        208     399     SF      -       -       0       ShADadfF        5       420     5       611     -
1511269488.593094       CfeRTH1oejGg6gA5Li      192.168.56.14   50446   51.15.197.127   80      tcp     http    0.121150        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269493.824701       CWmiwT4QR8u71xp0h       192.168.56.14   50447   51.15.197.127   80      tcp     http    0.126577        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269499.116879       C113hs4IWwgOGe0hxf      192.168.56.14   50448   51.15.197.127   80      tcp     http    0.122739        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269504.350011       CHI1AHQLm8ybrQ5ti       192.168.56.14   50449   51.15.197.127   80      tcp     http    0.117855        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269509.574454       CIpoyx4Sx3XEyiKbjh      192.168.56.14   50450   51.15.197.127   80      tcp     http    0.156094        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269514.842106       CDLbbm2nnHbr3RO9F9      192.168.56.14   50451   51.15.197.127   80      tcp     http    0.100951        208     399     SF      -       -       0       ShADadfF        5       420     5       611     -
1511269520.114079       CipCM33FvSh7hWVHnc      192.168.56.14   50452   51.15.197.127   80      tcp     http    0.135885        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269525.359633       CwMhAI3giczB1gTeR2      192.168.56.14   50453   51.15.197.127   80      tcp     http    0.105601        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269530.579134       CowTCpq1Lon2Rp5T2       192.168.56.14   50454   51.15.197.127   80      tcp     http    0.115933        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269535.801940       CpYwvc23LmuhPsuuMc      192.168.56.14   50455   51.15.197.127   80      tcp     http    0.106631        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269541.044084       Cnvsqj2QcNcWSLBqH7      192.168.56.14   50456   51.15.197.127   80      tcp     http    0.121668        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269546.278570       CgbzqfgMFulKOP1xe       192.168.56.14   50457   51.15.197.127   80      tcp     http    0.121052        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269551.506084       CUlFD949mmSfKATJpc      192.168.56.14   50458   51.15.197.127   80      tcp     http    0.096607        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269556.712264       Cbc1No4FSSjiRQFoNc      192.168.56.14   50459   51.15.197.127   80      tcp     http    0.137852        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269561.963394       CYwON91Js8ssOY4503      192.168.56.14   50460   51.15.197.127   80      tcp     http    0.099626        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269567.178812       Cryspb4A5KOHbIWDY       192.168.56.14   50461   51.15.197.127   80      tcp     http    0.154607        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269572.442802       CRpXje3yCwJlayfhnj      192.168.56.14   50462   51.15.197.127   80      tcp     http    0.104125        208     399     SF      -       -       0       ShADadfF        5       420     5       611     -
1511269577.652288       CkudtR34qPv7fMdMJ6      192.168.56.14   50463   51.15.197.127   80      tcp     http    0.099126        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269582.860772       Cmmlvl4K523e8SjCN6      192.168.56.14   50464   51.15.197.127   80      tcp     http    0.164748        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269588.129256       CPaFSTAJAIqVHwzPb       192.168.56.14   50465   51.15.197.127   80      tcp     http    0.109133        208     399     SF      -       -       0       ShADadfF        5       420     5       611     -
1511269593.348262       CVz6Zn4A42L2kupGIg      192.168.56.14   50466   51.15.197.127   80      tcp     http    0.120536        208     399     SF      -       -       0       ShADadfF        5       420     5       611     -
1511269598.574770       CHfjXhviIEXv6plH9       192.168.56.14   50467   51.15.197.127   80      tcp     http    0.121539        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269603.841610       CuLnP82MDaJG5EGhXf      192.168.56.14   50468   51.15.197.127   80      tcp     http    0.100802        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269609.055326       Cx6Ucw4sZSdBcmcIC4      192.168.56.14   50469   51.15.197.127   80      tcp     http    0.119905        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269614.297715       C1Fmoa1eqrmEFyfoZe      192.168.56.14   50470   51.15.197.127   80      tcp     http    0.101035        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269619.505350       C6d8iu18n9TSiDnsl2      192.168.56.14   50471   51.15.197.127   80      tcp     http    0.099847        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269624.718056       CmMGUH37oYmbgIBhlg      192.168.56.14   50472   51.15.197.127   80      tcp     http    0.105994        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269629.930502       CzI2GE1TrzEeBO1cTi      192.168.56.14   50473   51.15.197.127   80      tcp     http    0.101906        208     399     SF      -       -       0       ShADadfF        5       420     5       611     -
1511269635.148168       CjyA8G3Z8uvE4tJVF9      192.168.56.14   50474   51.15.197.127   80      tcp     http    0.119757        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269640.373506       CYyb4A2VWcRgAYvWag      192.168.56.14   50475   51.15.197.127   80      tcp     http    0.169011        199     287     SF      -       -       0       ShADadfF        5       411     5       499     -
1511269641.021152       CrYW4H0ghoFV71hA        192.168.56.14   50476   51.15.197.127   80      tcp     http    0.455491        438     399     SF      -       -       0       ShADadfF        6       690     6       651     -
1511269646.585189       CbUYsK3SLFNyu6kw1       192.168.56.14   50477   51.15.197.127   80      tcp     http    0.101870        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269651.808258       C9p1Kbt661hlXmlXj       192.168.56.14   50478   51.15.197.127   80      tcp     http    0.102826        204     399     SF      -       -       0       ShADadfF        5       416     5       611     -
1511269657.016924       CvxhCA2BroRtMx3fn8      192.168.56.14   50479   51.15.197.127   80      tcp     http    0.115444        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
1511269662.249219       C9uc9Y3j6g4RlJCQE7      192.168.56.14   50480   51.15.197.127   80      tcp     http    0.101768        199     399     SF      -       -       0       ShADadfF        5       411     5       611     -
#close  2023-07-16-12-15-40

```

If we look carefully enough we will notice connections being made to `51.15.197.127:80` approximately every 5 seconds, which is indicative of a malware beaconing.

The `psempire.pcap` file, which is located in the `/home/htb-student/pcaps` directory includes traffic related to PowerShell Empire. PowerShell Empire indeed beacons every 5 seconds in its default configuration.

### **Intrusion Detection With Zeek Example 2: Detecting DNS Exfiltration**

Zeek is also useful when we suspect data exfiltration. Data exfiltration can be difficult to detect as it often mimics normal network traffic. However, with Zeek, we can analyze our network traffic at a deeper level.

Zeek's **files.log** can be used to identify large amounts of data being sent to an unusual external destination, or over non-standard ports, which may suggest data exfiltration. The http.log and dns.log can also be utilized to identify potential covert exfiltration channels, such as DNS tunneling or HTTP POST requests to a suspicious domain.

```bash
$ /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/dnsexfil.pcapng
```

```bash
$ cat dns.log
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   dns
#open   2023-07-16-12-28-33
#fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   trans_id        rtt     query   qclass  qclass_name     qtype
        qtype_name      rcode   rcode_name      AA      TC      RD      RA      Z       answers TTLs    rejected
#types  time    string  addr    port    addr    port    enum    count   interval        string  count   string  count   string  count   string  bool    boolbool     bool    count   vector[string]  vector[interval]        bool
1630061362.889769       CogoDL3T2prsNPkXhe      192.168.38.104  65463   192.168.38.102  53      udp     53252   0.043481        safebrowsing.google.com 1   C_INTERNET       1       A       0       NOERROR F       F       T       T       0       sb.l.google.com,142.250.186.142 18994.000000,300.000000 F
1630061369.739218       CTlobe1QTqUhc1CzS3      192.168.38.104  56692   192.168.38.102  53      udp     32394   0.145503        456c54f2.blue.letsgohunt.onli
ne      1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       0.0.0.0 0.000000        F
1630061429.886391       CQPUxP37HbTlSOdLF6      192.168.38.104  49611   192.168.38.102  53      udp     64402   0.142414        456c54f2.blue.letsgohunt.onli
ne      1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       0.0.0.0 1.000000        F
1630061469.956241       C0JPXx3z0WuxTE9Tbg      192.168.38.103  51888   192.168.38.102  53      udp     34124   -       wpad.windomain.local    1       C_INT
ERNET   1       A       3       NXDOMAIN        F       F       T       F       0       -       -       F
1630061490.031632       CIMbmp4Wgt287yiERh      192.168.38.104  52584   192.168.38.102  53      udp     57411   0.143350        456c54f2.blue.letsgohunt.onli
ne      1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       0.0.0.241       1.000000        F
1630061490.175977       CLwvTc2MIadaIReXQd      192.168.38.104  61385   192.168.38.102  53      udp     31811   0.139366        www.180.0c9a5671.456c54f2.blu
e.letsgohunt.online     1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       0.0.0.0 1.000000        F
1630061490.316414       CqbrTf39jEUB1hHd37      192.168.38.104  60333   192.168.38.102  53      udp     41259   0.137040        www.1204192da26d109d4.1c9a567
1.456c54f2.blue.letsgohunt.online       1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       0.0.0.0 0.000000    F
1630061490.454478       CQAWsr3oTT6nmG7Hp4      192.168.38.104  53312   192.168.38.102  53      udp     28300   0.143220        www.11a1855b98d2b71c3.2c9a567
1.456c54f2.blue.letsgohunt.online       1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       0.0.0.0 1.000000    F
1630061490.598615       CF17ZJ2eHvUosEjVC       192.168.38.104  64078   192.168.38.102  53      udp     33505   0.142812        www.122aa166873fda051.3c9a567
1.456c54f2.blue.letsgohunt.online       1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       0.0.0.0 1.000000    F
1630061490.742694       CS0QSmWZe9bUEpNwf       192.168.38.104  54465   192.168.38.102  53      udp     5391    0.144439        www.1d91f26756080c945.4c9a567
1.456c54f2.blue.letsgohunt.online       1       C_INTERNET      1       A       0       NOERROR F       F       T       T       0       0.0.0.0 1.000000    F
---SNIP---
```

Let's focus on the requested (sub)domains by leveraging `zeek-cut`

```bash
$ cat dns.log | /usr/local/zeek/bin/zeek-cut query | cut -d . -f1-7
safebrowsing.google.com
456c54f2.blue.letsgohunt.online
456c54f2.blue.letsgohunt.online
wpad.windomain.local
456c54f2.blue.letsgohunt.online
www.180.0c9a5671.456c54f2.blue.letsgohunt.online
www.1204192da26d109d4.1c9a5671.456c54f2.blue.letsgohunt.online
www.11a1855b98d2b71c3.2c9a5671.456c54f2.blue.letsgohunt.online
www.122aa166873fda051.3c9a5671.456c54f2.blue.letsgohunt.online
www.1d91f26756080c945.4c9a5671.456c54f2.blue.letsgohunt.online
www.1302c3663cc8a94f9.5c9a5671.456c54f2.blue.letsgohunt.online
www.1adef2977e4b3653f.6c9a5671.456c54f2.blue.letsgohunt.online
www.111edd479a7512c9c.7c9a5671.456c54f2.blue.letsgohunt.online
www.11483ec078e733131.8c9a5671.456c54f2.blue.letsgohunt.online
www.1f5e94740470d0157.9c9a5671.456c54f2.blue.letsgohunt.online
www.114cbea690a81874a.ac9a5671.456c54f2.blue.letsgohunt.online
www.10db7634eade0b736.bc9a5671.456c54f2.blue.letsgohunt.online
www.1d5aee37e1c25ba02.cc9a5671.456c54f2.blue.letsgohunt.online
www.1d4f517cdcf8807c2.dc9a5671.456c54f2.blue.letsgohunt.online
www.14d71477201813b75.ec9a5671.456c54f2.blue.letsgohunt.online
www.1e3723505f4ebd907.fc9a5671.456c54f2.blue.letsgohunt.online
www.1aa645b2d.10c9a5671.456c54f2.blue.letsgohunt.online
www.1cf2bfe54.11c9a5671.456c54f2.blue.letsgohunt.online
cdn.0600553f0.456c54f2.blue.letsgohunt.online
cdn.1600553f0.456c54f2.blue.letsgohunt.online
cdn.2600553f0.456c54f2.blue.letsgohunt.online
cdn.3600553f0.456c54f2.blue.letsgohunt.online
cdn.4600553f0.456c54f2.blue.letsgohunt.online
cdn.5600553f0.456c54f2.blue.letsgohunt.online
cdn.6600553f0.456c54f2.blue.letsgohunt.online
cdn.7600553f0.456c54f2.blue.letsgohunt.online
cdn.8600553f0.456c54f2.blue.letsgohunt.online
cdn.9600553f0.456c54f2.blue.letsgohunt.online
cdn.a600553f0.456c54f2.blue.letsgohunt.online
cdn.b600553f0.456c54f2.blue.letsgohunt.online
cdn.c600553f0.456c54f2.blue.letsgohunt.online
cdn.d600553f0.456c54f2.blue.letsgohunt.online
cdn.e600553f0.456c54f2.blue.letsgohunt.online
cdn.f600553f0.456c54f2.blue.letsgohunt.online
cdn.10600553f0.456c54f2.blue.letsgohunt.online
post.140.0346c53ab.456c54f2.blue.letsgohunt.online
post.10bb13b53.1346c53ab.456c54f2.blue.letsgohunt.online
post.104fb3984.2346c53ab.456c54f2.blue.letsgohunt.online
post.1bdfe1d1e.3346c53ab.456c54f2.blue.letsgohunt.online
post.19f3acfa6.4346c53ab.456c54f2.blue.letsgohunt.online
post.18daa4c69.5346c53ab.456c54f2.blue.letsgohunt.online
post.107f7e44c.6346c53ab.456c54f2.blue.letsgohunt.online
post.1ab508fac.7346c53ab.456c54f2.blue.letsgohunt.online
post.18ae33d21.8346c53ab.456c54f2.blue.letsgohunt.online
post.11edd6ce8.9346c53ab.456c54f2.blue.letsgohunt.online
post.1979ee0a5.a346c53ab.456c54f2.blue.letsgohunt.online
post.1cc9dd9e9.b346c53ab.456c54f2.blue.letsgohunt.online
post.17b865d4d.c346c53ab.456c54f2.blue.letsgohunt.online
post.1212da6de.d346c53ab.456c54f2.blue.letsgohunt.online
post.177a1fc1a.e346c53ab.456c54f2.blue.letsgohunt.online
post.19e7d023b.f346c53ab.456c54f2.blue.letsgohunt.online
post.1100b6576.10346c53ab.456c54f2.blue.letsgohunt.online
www.1f5e94740470d0157.9c9a5671.456c54f2.blue.letsgohunt.online
sgtqrgcask.windomain.local
zvfepxzuazrlds.windomain.local
kohaqbopxlq.windomain.local
www.1cf2bfe54.11c9a5671.456c54f2.blue.letsgohunt.online
sgtqrgcask.windomain.local
zvfepxzuazrlds.windomain.local
kohaqbopxlq.windomain.local
456c54f2.blue.letsgohunt.online
wpad.windomain.local
456c54f2.blue.letsgohunt.online
456c54f2.blue.letsgohunt.online
cdn.013821c34.456c54f2.blue.letsgohunt.online
cdn.113821c34.456c54f2.blue.letsgohunt.online
cdn.213821c34.456c54f2.blue.letsgohunt.online
cdn.313821c34.456c54f2.blue.letsgohunt.online
cdn.313821c34.456c54f2.blue.letsgohunt.online
cdn.413821c34.456c54f2.blue.letsgohunt.online
cdn.513821c34.456c54f2.blue.letsgohunt.online
cdn.613821c34.456c54f2.blue.letsgohunt.online
cdn.713821c34.456c54f2.blue.letsgohunt.online
cdn.813821c34.456c54f2.blue.letsgohunt.online
cdn.913821c34.456c54f2.blue.letsgohunt.online
cdn.a13821c34.456c54f2.blue.letsgohunt.online
cdn.b13821c34.456c54f2.blue.letsgohunt.online
cdn.c13821c34.456c54f2.blue.letsgohunt.online
456c54f2.blue.letsgohunt.online
456c54f2.blue.letsgohunt.online
456c54f2.blue.letsgohunt.online
456c54f2.blue.letsgohunt.online
456c54f2.blue.letsgohunt.online
v10.vortex-win.data.microsoft.com
456c54f2.blue.letsgohunt.online
456c54f2.blue.letsgohunt.online
456c54f2.blue.letsgohunt.online
---SNIP---
post.1460.0467121d5.456c54f2.blue.letsgohunt.online
post.11a878166.1467121d5.456c54f2.blue.letsgohunt.online
post.12c1c89cf.2467121d5.456c54f2.blue.letsgohunt.online
post.1bdcdb1fb.3467121d5.456c54f2.blue.letsgohunt.online
post.1a6c6349c.4467121d5.456c54f2.blue.letsgohunt.online
post.14f3d0809.5467121d5.456c54f2.blue.letsgohunt.online
post.172d6c024.6467121d5.456c54f2.blue.letsgohunt.online
post.162ef0f19.7467121d5.456c54f2.blue.letsgohunt.online
post.15b5a7d2f.8467121d5.456c54f2.blue.letsgohunt.online
post.1286fe5b0.9467121d5.456c54f2.blue.letsgohunt.online
post.1fe01b96d.a467121d5.456c54f2.blue.letsgohunt.online
post.1ed530f2f.b467121d5.456c54f2.blue.letsgohunt.online
post.1c8d291d4.c467121d5.456c54f2.blue.letsgohunt.online
post.153699937.d467121d5.456c54f2.blue.letsgohunt.online
post.158c0e1f4.e467121d5.456c54f2.blue.letsgohunt.online
post.139cc5d29.f467121d5.456c54f2.blue.letsgohunt.online
post.1e189482f.10467121d5.456c54f2.blue.letsgohunt.online
post.189c8f742.11467121d5.456c54f2.blue.letsgohunt.online
post.1f6a4e146.12467121d5.456c54f2.blue.letsgohunt.online
post.16ec2a953.13467121d5.456c54f2.blue.letsgohunt.online
post.170c0d25b.14467121d5.456c54f2.blue.letsgohunt.online
post.113540390.15467121d5.456c54f2.blue.letsgohunt.online
post.1ca92006c.16467121d5.456c54f2.blue.letsgohunt.online
post.19092e499.17467121d5.456c54f2.blue.letsgohunt.online
post.1767e291d.18467121d5.456c54f2.blue.letsgohunt.online
post.15bb03130.19467121d5.456c54f2.blue.letsgohunt.online
post.180fe71ad.1a467121d5.456c54f2.blue.letsgohunt.online
post.196a0026d.1b467121d5.456c54f2.blue.letsgohunt.online
post.11a2ec7e4.1c467121d5.456c54f2.blue.letsgohunt.online
post.179b5c2cb.1d467121d5.456c54f2.blue.letsgohunt.online
post.1065838ef.1e467121d5.456c54f2.blue.letsgohunt.online
post.10113b20d.1f467121d5.456c54f2.blue.letsgohunt.online
post.1d78debc8.20467121d5.456c54f2.blue.letsgohunt.online
post.155a1b219.21467121d5.456c54f2.blue.letsgohunt.online
post.1b7ccee56.22467121d5.456c54f2.blue.letsgohunt.online
post.13cbcd295.23467121d5.456c54f2.blue.letsgohunt.online
post.1adefc484.24467121d5.456c54f2.blue.letsgohunt.online
post.1cf6a99a5.25467121d5.456c54f2.blue.letsgohunt.online
post.1cc391010.26467121d5.456c54f2.blue.letsgohunt.online
post.18f94bc21.27467121d5.456c54f2.blue.letsgohunt.online
post.1bfb7033c.28467121d5.456c54f2.blue.letsgohunt.online
post.18e36fa94.29467121d5.456c54f2.blue.letsgohunt.online
post.1d141f783.2a467121d5.456c54f2.blue.letsgohunt.online
post.16a96aac3.2b467121d5.456c54f2.blue.letsgohunt.online
post.1f30c5795.2c467121d5.456c54f2.blue.letsgohunt.online
post.196711e3e.2d467121d5.456c54f2.blue.letsgohunt.online
post.1297f6300.2e467121d5.456c54f2.blue.letsgohunt.online
post.16e18e7dd.2f467121d5.456c54f2.blue.letsgohunt.online
post.16a187dd4.30467121d5.456c54f2.blue.letsgohunt.online
post.1b164078f.31467121d5.456c54f2.blue.letsgohunt.online
post.15e30ba0e.32467121d5.456c54f2.blue.letsgohunt.online
post.1829f67d4.33467121d5.456c54f2.blue.letsgohunt.online
post.17675f25b.34467121d5.456c54f2.blue.letsgohunt.online
post.135fc439b.35467121d5.456c54f2.blue.letsgohunt.online
post.13c0803cb.36467121d5.456c54f2.blue.letsgohunt.online
post.1dbcb3f1b.37467121d5.456c54f2.blue.letsgohunt.online
---SNIP---

```

Upon close inspection, it becomes evident that the domain `letsgohunt.online` possesses a significant number of subdomains, similar to cloud providers. However, it's worth noting that interactions with dozens or even hundreds of subdomains are generally not considered typical behavior.

### **Intrusion Detection With Zeek Example 3: Detecting TLS Exfiltration**

Let's now go over an example of detecting data exfiltration over TLS.

```bash
$ /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/tlsexfil.pcap
```

```bash
$ cat conn.log
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   conn
#open   2023-07-16-12-48-53
#fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   service duration        orig_bytes      resp_bytes      conn_
state   local_orig      local_resp      missed_bytes    history orig_pkts       orig_ip_bytes   resp_pkts       resp_ip_bytes   tunnel_parents
#types  time    string  addr    port    addr    port    enum    string  interval        count   count   string  bool    bool    count   string  count   count
        count   count   set[string]
1628867750.258715       CdU24818il2WrB5gx9      fe80::4996:7026:833f:a154       546     ff02::1:2       547     udp     -       -       -       -       S0  --       0       D       1       152     0       0       -
1628867814.448052       CD4narIi677g3tdG7       10.0.10.100     54754   192.168.151.181 443     tcp     ssl     0.097507        646     1452    SF      -   -0       ShADadfFR       15      1258    13      1984    -
1628867874.573558       CCXldM1iyIuyhNiBe2      10.0.10.100     53905   192.168.151.181 443     tcp     ssl     0.021315        636     410     SF      -   -0       ShADadfF        9       1008    9       782     -
1628867877.614701       Cg9e9K1AuI0k4cLZd9      10.0.10.100     53906   192.168.151.181 443     tcp     ssl     0.010393        636     316     SF      -   -0       ShADadfFR       10      1048    9       688     -
1628867883.643943       CA91RA1mwdLcwUJbEi      10.0.10.100     53931   192.168.151.181 443     tcp     ssl     0.007428        636     394     SF      -   -0       ShADadfF        10      1048    9       766     -
1628867880.629877       CpYf8hQlyAnrcCcm3       10.0.10.100     53907   192.168.151.181 443     tcp     ssl     6.044923        636     316     SF      -   -0       ShADadfFR       11      1088    9       688     -
1628867883.655898       CGYvJ3saMB5dphXmd       10.0.10.100     53932   192.168.151.181 443     tcp     ssl     6.032257        602     301     SF      -   -0       ShADadfFR       11      1054    9       673     -
1628867889.688558       CM7Uex4iNNNdDuXQI9      10.0.10.100     53935   192.168.151.181 443     tcp     ssl     0.058204        636     761668  SF      -   -0       ShADadfFR       251     10688   530     782880  -
1628867890.907805       CA797aXtJqeOtKwq2       10.0.10.100     53936   192.168.151.181 443     tcp     ssl     0.007216        6489    301     SF      -   -0       ShADadfFR       15      7101    13      833     -
1628867886.675238       CMSija4yWhe79PvBRa      10.0.10.100     53933   192.168.151.181 443     tcp     ssl     10.263047       636     316     SF      -   -0       ShADadfFR       11      1088    9       688     -
1628867893.923082       C08H2y2GdUfnpjolb8      10.0.10.100     53937   192.168.151.181 443     tcp     ssl     6.030951        636     316     SF      -   -0       ShADadfFR       11      1088    9       688     -
1628867896.938711       CkM3724NFKT3yly1ba      10.0.10.100     53938   192.168.151.181 443     tcp     ssl     6.030904        636     316     SF      -   -0       ShADadfFR       11      1088    9       688     -
1628867902.969959       CPT4hK31bvSaURqWH3      10.0.10.100     53940   192.168.151.181 443     tcp     ssl     0.007301        636     316     SF      -   -0       ShADadfFR       10      1048    9       688     -
1628867899.954481       Ccz3Dq202Zm8LFrzWl      10.0.10.100     53939   192.168.151.181 443     tcp     ssl     9.046324        636     316     SF      -   -0       ShADadfFR       11      1088    9       688     -
1628867909.001101       C19Vw03nPSvVEqus6a      10.0.10.100     53943   192.168.151.181 443     tcp     ssl     0.006624        636     316     SF      -   -0       ShADadfFR       10      1048    9       688     -
1628867912.016361       CNhVAiOpkgAh1R8sc       10.0.10.100     53944   192.168.151.181 443     tcp     ssl     0.006317        636     316     SF      -   -0       ShADadfFR       11      1088    10      728     -
1628867813.135021       C6tGC34oP3F21KORAa      10.0.10.100     54753   192.168.151.181 80      tcp     http    100.022854      71      223946  SF      -   -0       ShADadfFr       61      2523    158     230278  -
1628867915.031768       CFt2xn0eYzCSJ8Tm3       10.0.10.100     53945   192.168.151.181 443     tcp     ssl     0.006337        636     316     SF      -   -0       ShADadfFR       10      1048    9       688     -
1628867905.985349       CVQgKN1WiXXgZIEy16      10.0.10.100     53941   192.168.151.181 443     tcp     ssl     15.077758       636     316     SF      -   -0       ShADadfFR       11      1088    9       688     -
1628867921.063426       CPAfjN16aDWelGoQa5      10.0.10.100     53947   192.168.151.181 443     tcp     ssl     0.006175        636     316     SF      -   -0       ShADadfFR       10      1048    9       688     -
1628867924.078851       C0p8fW3d4pYpG44Jph      10.0.10.100     53948   192.168.151.181 443     tcp     ssl     0.006009        636     394     SF      -   -0       ShADadfF        10      1048    9       766     -
1628867924.087301       CEw1Dx2GLoPquSbp4a      10.0.10.100     53949   192.168.151.181 443     tcp     ssl     0.006812        635     301     SF      -   -0       ShADadfFR       11      1087    9       673     -
1628867918.047485       CgnReehqaJvQprHy        10.0.10.100     53946   192.168.151.181 443     tcp     ssl     6.375404        636     316     SF      -   -0       ShADadfFR       11      1088    9       688     -
1628867927.110654       CkC7Zh1hj0i8MwNLJ4      10.0.10.100     53951   192.168.151.181 443     tcp     ssl     0.012658        636     94934   SF      -   -0       ShADadfF        40      2248    73      97866   -
1628867931.281818       CaKMQO2fekZSAErjP       10.0.10.100     53952   192.168.151.181 443     tcp     ssl     0.005757        636     316     SF      -   -0       ShADadfFR       10      1048    9       688     -
1628867931.288461       CjcDcAwMHgOaoxGu6       10.0.10.100     53953   192.168.151.181 443     tcp     ssl     0.005921        635     301     SF      -   -0       ShADadfFR       11      1087    9       673     -
1628867934.297398       CiEfhC2odzlHli49Q2      10.0.10.100     53954   192.168.151.181 443     tcp     ssl     0.006077        636     316     SF      -   -0       ShADadfFR       10      1048    9       688     -
1628867937.313352       CfW6Lb4WRMgJUS7Rn8      10.0.10.100     53955   192.168.151.181 443     tcp     ssl     3.022240        636     316     SF      -   -0       ShADadfFR       11      1088    9       688     -
1628867940.328753       CerXJm10bIAxgVVqz5      10.0.10.100     53956   192.168.151.181 443     tcp     ssl     3.015564        636     316     SF      -   -0       ShADadfFR       11      1088    9       688     -
1628867940.336125       CsAfy6jGo3uLtDAA5       10.0.10.100     53957   192.168.151.181 443     tcp     ssl     6.023655        635     301     SF      -   -0       ShADadfFR       11      1087    9       673     -
1628867946.360157       CFtJB71l1uIyBiy4bl      10.0.10.100     53959   192.168.151.181 443     tcp     ssl     0.006221        636     316     SF      -   -0       ShADadfFR       11      1088    9       688     -
1628867949.375797       CXmWZc344kNYukfAZa      10.0.10.100     53961   192.168.151.181 443     tcp     ssl     0.005946        636     316     SF      -   -0       ShADadfFR       10      1048    9       688     -
1628867943.344713       C0tEUWB7VYkFzPRVk       10.0.10.100     53958   192.168.151.181 443     tcp     ssl     12.062123       636     316     SF      -   -0       ShADadfFR       11      1088    9       688     -
1628867955.407292       C4BsWIqN2EivsCq78       10.0.10.100     60677   192.168.151.181 443     tcp     ssl     0.006345        636     316     SF      -   -0       ShADadfFR       10      1048    9       688     -
1628867952.391209       CQ16vl3UTaFE6CAuP1      10.0.10.100     53962   192.168.151.181 443     tcp     ssl     6.037476        636     316     SF      -   -0       ShADadfFR       11      1088    9       688     -
1628867958.429096       CCgRqF34Zw0NJKdtc7      10.0.10.100     61579   192.168.151.181 443     tcp     ssl     0.005344        602     301     SF      -   -0       ShADadfFR       10      1014    9       673     -
1628867959.112081       CrCSPSO195LUPz6t2       10.0.10.100     61682   10.0.10.1       6000    tcp     -       3.013302        0       0       S0      -   -0       S       3       156     0       0       -
1628867959.112205       CCuH0D1XNvS6KOMR4j      10.0.10.100     61683   10.0.10.1       5999    tcp     -       3.013185        0       0       S0      -   -0       S       3       156     0       0       -
1628867959.112399       CpYbPQ1Ea1arKY1GQk      10.0.10.100     61684   10.0.10.1       5998    tcp     -       3.012992        0       0       S0      -   -0       S       3       156     0       0       -
1628867959.112573       CpHaau3yHk4ZtqPtS2      10.0.10.100     61685   10.0.10.1       5997    tcp     -       3.012820        0       0       S0      -   -0       S       3       156     0       0       -
1628867959.112748       CISSiF3c92oAe9BJPd      10.0.10.100     61686   10.0.10.1       5996    tcp     -       3.012646        0       0       S0      -   -0       S       3       156     0       0       -
---SNIP---
```

The output is a bit tricky to analyze. Let's narrow things down by using `zeek-cut`

```bash
$ cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes | sort | grep -v -e '^$' | grep -v '-' | datamash -g 1,2 sum 3 | sort -k 3 -rn | head -10
10.0.10.100     192.168.151.181 270775912
10.0.10.100     10.0.10.1       0

```

### **Intrusion Detection With Zeek Example 4: Detecting PsExec**

**PsExec**, a part of the Sysinternals Suite, is frequently used for remote administration within Active Directory environments.

To illustrate a typical attack sequence, let's consider this: an attacker transfers the binary file `PSEXESVC.exe` to a target machine using the `ADMIN$` share, a special shared folder used in Windows networks, via the SMB protocol. Following this, the attacker remotely launches this file as a temporary service by utilizing the `IPC$` share, another special shared resource that enables *Inter-Process Communication*. 

We can identify SMB transfers and the typical use of `PsExec` using Zeek's `smb_files.log`, `dce_rpc.log`, and `smb_mapping.log`:

```bash
$ /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/psexec_add_user.pcap
```

```bash
$ cat smb_files.log
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   smb_files
#open   2023-07-16-17-39-49
#fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    action  path    name    size    prev_name       times.modified  times.accessed        times.created   times.changed
#types  time    string  addr    port    addr    port    string  enum    string  string  count   string  time    time    time    time
1507567479.268789       CksrR04Pziy7EPYOT6      192.168.10.31   49282   192.168.10.10   445     -       SMB::FILE_OPEN  \\\\dc1\\ADMIN$ PSEXESVC.exe    0       -    1507567479.122923        1507567479.122923       1507567479.122923       1507567479.122923
1507567500.496785       CgPykN2qCki9kzhoh6      192.168.10.31   49285   192.168.10.10   445     -       SMB::FILE_OPEN  \\\\dc1\\ADMIN$ PSEXESVC.exe    145568  -    1507567479.122923        1507567479.122923       1507567479.122923       1507567479.122923
1507567500.496785       CgPykN2qCki9kzhoh6      192.168.10.31   49285   192.168.10.10   445     -       SMB::FILE_DELETE        \\\\dc1\\ADMIN$ PSEXESVC.exe    145568-       1507567479.122923       1507567479.122923       1507567479.122923       1507567479.122923
#close  2023-07-16-17-39-49
```

```bash
$ cat smb_files.log
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   smb_files
#open   2023-07-16-17-39-49
#fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    action  path    name    size    prev_name       times.modified  times.accessed        times.created   times.changed
#types  time    string  addr    port    addr    port    string  enum    string  string  count   string  time    time    time    time
1507567479.268789       CksrR04Pziy7EPYOT6      192.168.10.31   49282   192.168.10.10   445     -       SMB::FILE_OPEN  \\\\dc1\\ADMIN$ PSEXESVC.exe    0       -    1507567479.122923        1507567479.122923       1507567479.122923       1507567479.122923
1507567500.496785       CgPykN2qCki9kzhoh6      192.168.10.31   49285   192.168.10.10   445     -       SMB::FILE_OPEN  \\\\dc1\\ADMIN$ PSEXESVC.exe    145568  -    1507567479.122923        1507567479.122923       1507567479.122923       1507567479.122923
1507567500.496785       CgPykN2qCki9kzhoh6      192.168.10.31   49285   192.168.10.10   445     -       SMB::FILE_DELETE        \\\\dc1\\ADMIN$ PSEXESVC.exe    145568-       1507567479.122923       1507567479.122923       1507567479.122923       1507567479.122923
#close  2023-07-16-17-39-49
```

```bash
$ cat smb_mapping.log
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   smb_mapping
#open   2023-07-16-17-39-49
#fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       path    service native_file_system      share_type
#types  time    string  addr    port    addr    port    string  string  string  string
1507567479.268407       CksrR04Pziy7EPYOT6      192.168.10.31   49282   192.168.10.10   445     \\\\dc1\\ADMIN$ -       -       DISK
1507567500.280462       CgPykN2qCki9kzhoh6      192.168.10.31   49285   192.168.10.10   445     \\\\dc1\\IPC$   -       -       PIPE
1507567500.496371       CgPykN2qCki9kzhoh6      192.168.10.31   49285   192.168.10.10   445     \\\\dc1\\ADMIN$ -       -       DISK
#close  2023-07-16-17-39-49
```

The temporary service creation is apparent in the last two logs above.