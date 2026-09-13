import json

KNOWLEDGE = {
    "SYN": {
        "mechanism": "TCP SYN Flood targets the stateful nature of the Transmission Control Protocol (RFC 793) 3-way handshake. The attacker transmits a rapid barrage of TCP SYN packets with spoofed source IP addresses or ignores subsequent server responses. Upon receiving each SYN packet, the victim allocates kernel memory for a Transmission Control Block (TCB) in the half-open SYN_RECV state and returns a SYN-ACK packet. Because the attacker never returns the final ACK, these half-open connections remain held until timeout, completely exhausting the operating system listen backlog queue (tcp_max_syn_backlog). Consequently, legitimate client SYN packets are silently dropped. Flow telemetry exhibits a severely skewed SYN-to-ACK packet ratio approaching infinity, repetitive minimal packet sizes of 40-60 bytes without payload, randomized ephemeral source ports, and sub-millisecond inter-arrival intervals.",
        "port": 80,
        "protocol": "TCP",
        "factor": "N/A",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p tcp --syn --dport 80 -m limit --limit 20/s --limit-burst 50 -j ACCEPT\niptables -A INPUT -p tcp --syn --dport 80 -j DROP",
        "cisco": "ip tcp intercept list 100\nip tcp intercept max-incomplete high 1000 low 800\nip tcp intercept connection-timeout 30",
        "tc": "tc qdisc add dev eth0 root handle 1: htb default 10\ntc class add dev eth0 parent 1: classid 1:10 htb rate 50mbit ceil 100mbit"
    },
    "UDP": {
        "mechanism": "Volumetric UDP Flood abuses the connectionless nature of the User Datagram Protocol (RFC 768). The adversary inundates targeted host interfaces or randomized high ports (1024-65535) with massive volumes of UDP datagrams. Because UDP lacks handshaking or congestion control, the victim operating system must process incoming packet headers, check for listening sockets across its protocol port table, and when no listening application exists, generate and transmit an ICMP Destination Unreachable (Port Unreachable, Type 3 Code 3) packet. This process rapidly exhausts CPU cycles via software interrupts (softirqs), saturates kernel socket receive buffers (sk_buff), and completely consumes physical network link bandwidth. Telemetry indicates a drastic surge in packet rate (PPS) and byte rate (BPS), zero TCP flag presence, uniformly distributed destination ports, and near-zero inter-packet arrival jitter.",
        "port": 80,
        "protocol": "UDP",
        "factor": "1x",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p udp -m limit --limit 100/s --limit-burst 200 -j ACCEPT\niptables -A INPUT -p udp -j DROP",
        "cisco": "access-list 101 deny udp any any eq 80\nrate-limit input 10000000 10000 20000 conform-action transmit exceed-action drop",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip protocol 17 0xff flowid 1:10"
    },
    "UDP-Lag": {
        "mechanism": "UDP-Lag (also known as packet stuttering or desynchronization flooding) is an evasive denial-of-service attack specifically tailored against real-time UDP-based interactive services such as online gaming, VoIP (RTP), and streaming. Attackers craft bursts of oversized UDP packets near or exceeding the Maximum Transmission Unit (MTU), often triggering IP fragmentation (RFC 791). By interleaving high-frequency micro-bursts with intermittent pauses, the attack avoids steady-state rate-limiting thresholds while inducing massive buffer bloat, queue delay, and severe packet loss inside the operating system network stack. As a result, connection buffers overflow, real-time UDP state tracking desynchronizes, and interactive sessions experience unbearable latency spikes and timeouts. Telemetry reveals anomalous burstiness in packet arrival variance, packet lengths fluctuating between 1400 and 1500 bytes, and significant packet reordering.",
        "port": 80,
        "protocol": "UDP",
        "factor": "1x",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p udp -m length --length 1400:65535 -j DROP",
        "cisco": "access-list 101 deny udp any any range 1024 65535\nrate-limit input 5000000 5000 10000 conform-action transmit exceed-action drop",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip protocol 17 0xff match u16 0x0578 0xffff at 2 flowid 1:10"
    },
    "ICMP": {
        "mechanism": "ICMP Echo Flood (Ping Flood) saturates network links and host compute resources by transmitting an overwhelming volume of ICMP Echo Request packets (RFC 792, Type 8 Code 0). The victim host kernel is obligated to process each incoming request at the operating system network layer and generate a corresponding ICMP Echo Reply (Type 0 Code 0). When launched at volumetric scale, incoming packet processing triggers extreme CPU interrupt handling overhead, saturates network interface card (NIC) ring buffers, and starves outbound bandwidth. Historical variants such as Smurf attacks amplify this impact by broadcasting requests to directed subnet broadcast addresses with spoofed victim source IPs. NetFlow signatures demonstrate high PPS with exclusively protocol number 1, identical payload byte sequences, uniform packet sizes (typically 64, 84, or 1000+ bytes), and equal bidirectional packet generation requirements.",
        "port": 0,
        "protocol": "ICMP",
        "factor": "1x",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT\niptables -A INPUT -p icmp --icmp-type echo-request -j DROP",
        "cisco": "access-list 101 deny icmp any any echo\naccess-list 101 permit icmp any any echo-reply",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip protocol 1 0xff flowid 1:10"
    },
    "DNS": {
        "mechanism": "Distributed Reflection Denial of Service (DrDoS) DNS Amplification exploits publicly accessible open recursive DNS resolvers (RFC 1035). The attacker sends small DNS query packets (approx. 40-60 bytes) with the source IP address spoofed to match the victim target. Queries typically request ANY, large TXT, or DNSSEC-enabled Resource Records (EDNS0, RFC 6891) for specifically registered domains. The open DNS resolvers process the legitimate requests and return bloated DNS response packets ranging from 1,500 to 4,000+ bytes directly to the victim target IP. This generates a massive amplification factor of 28x to 54x, turning modest botnet upstream bandwidth into tens or hundreds of gigabits of inbound traffic. NetFlow telemetry exhibits heavy inbound UDP traffic originating exclusively from source port 53, packet lengths frequently clamped at MTU thresholds (1400-1500 bytes), and high byte-to-packet ratio.",
        "port": 53,
        "protocol": "UDP",
        "factor": "28x-54x",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p udp --sport 53 -m length --length 512:65535 -j DROP\niptables -A INPUT -p udp --dport 53 -m string --hex-string '|0000ff0001|' --algo bm -j DROP",
        "cisco": "access-list 101 deny udp any eq 53 any\nrate-limit input 2000000 5000 10000 conform-action transmit exceed-action drop",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip sport 53 0xffff flowid 1:10"
    },
    "NTP": {
        "mechanism": "DrDoS NTP Amplification exploits vulnerable Network Time Protocol daemons (RFC 5905) running obsolete versions supporting the private mode 7 monlist diagnostic command (CVE-2013-5211). The attacker transmits a tiny 8-byte UDP query packet containing the monlist command to open NTP servers worldwide, spoofing the victim target IP. The NTP daemon responds with up to 100 consecutive UDP packets containing telemetry records of the last 600 clients that queried the time server. This creates an extraordinary amplification factor reaching 556x to 1,000x, allowing low-powered attackers to completely overwhelm enterprise transit links. Traffic signatures show incoming UDP flows originating from UDP source port 123, containing fragmented datagrams with constant payloads of 440-482 bytes, and rapid bursts per individual reflector IP.",
        "port": 123,
        "protocol": "UDP",
        "factor": "556x-1000x",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p udp --sport 123 -m length --length 400:65535 -j DROP\niptables -A INPUT -p udp --dport 123 -m string --hex-string '|1700032a|' --algo bm -j DROP",
        "cisco": "access-list 101 deny udp any eq 123 any\nntp disable",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip sport 123 0xffff flowid 1:10"
    },
    "SNMP": {
        "mechanism": "Simple Network Management Protocol (SNMP) Reflection Amplification leverages public or misconfigured SNMP agents (RFC 1157, RFC 3416) on UDP port 161 with default community strings such as 'public' or 'private'. Attackers send small GetBulkRequest or GetNextRequest packets specifying high max-repetitions, with spoofed victim source IPs. The reflector agent walks its entire Management Information Base (MIB) tree, returning serialized device status tables, interface statistics, and routing data in bloated response packets. This results in an amplification factor between 6x and 11x. Telemetry demonstrates UDP flows originating from source port 161, elevated packet payload sizes often fragmented across multiple packets, and steady high-bandwidth throughput targeting victim services.",
        "port": 161,
        "protocol": "UDP",
        "factor": "6x-11x",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p udp --sport 161 -j DROP\niptables -A INPUT -p udp --dport 161 -m string --string 'public' --algo bm -j DROP",
        "cisco": "no snmp-server community public RO\naccess-list 101 deny udp any eq 161 any",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip sport 161 0xffff flowid 1:10"
    },
    "SSDP": {
        "mechanism": "Simple Service Discovery Protocol (SSDP) Amplification exploits Universal Plug and Play (UPnP) devices exposed to the public Internet on UDP port 1900. Threat actors forge victim IP addresses and broadcast M-SEARCH discovery queries with search targets such as 'ssdp:all' or 'upnp:rootdevice'. Home routers, smart TVs, and IoT endpoints respond by returning detailed device descriptions, XML service schemas, and location headers. This yields an amplification factor of approximately 30x. Network telemetry reveals volumetric UDP streams originating from ephemeral external hosts via UDP source port 1900, with ASCII HTTP-like headers (HTTP/1.1 200 OK, ST:, USN:, LOCATION:) in the payload, creating severe edge firewall connection state exhaustion.",
        "port": 1900,
        "protocol": "UDP",
        "factor": "30x",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p udp --sport 1900 -j DROP\niptables -A INPUT -p udp --dport 1900 -j DROP",
        "cisco": "access-list 101 deny udp any eq 1900 any\naccess-list 101 deny udp any any eq 1900",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip sport 1900 0xffff flowid 1:10"
    },
    "LDAP": {
        "mechanism": "Connectionless Lightweight Directory Access Protocol (CLDAP) Reflection abuses Microsoft Active Directory domain controllers and public LDAP servers operating on UDP port 389 (RFC 2251, RFC 4511). Attackers dispatch a small search request (approx. 50-70 bytes) querying rootDSE base object attributes with filter '(&(objectClass=*))', spoofing the victim target IP address. The domain controller responds with comprehensive enterprise directory metadata, configuration partitions, and naming contexts totaling thousands of bytes, achieving an amplification ratio of 46x to 55x. NetFlow characteristics display concentrated UDP traffic from source port 389 with large average packet sizes (1200-1400 bytes), high byte rate vs packet rate ratios, and rapid saturation of victim access routers.",
        "port": 389,
        "protocol": "UDP",
        "factor": "46x-55x",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p udp --sport 389 -j DROP\niptables -A INPUT -p udp --dport 389 -j DROP",
        "cisco": "access-list 101 deny udp any eq 389 any\naccess-list 101 deny udp any any eq 389",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip sport 389 0xffff flowid 1:10"
    },
    "MSSQL": {
        "mechanism": "Microsoft SQL Server Resolution Protocol (MC-SQLR) Amplification exploits the SQL Server Browser service listening on UDP port 1434. Attackers transmit a single 1-byte request packet containing opcode 0x02 (CLNT_BCAST_EX) with the spoofed source IP of the target victim. The SQL Server Resolution service responds with a detailed text string describing all active SQL Server instances, service names, named pipes, and TCP port configurations. This generates a reflection amplification factor of 25x. Network signatures show incoming UDP datagrams originating from source port 1434 directed to arbitrary destination ports, containing semi-colon delimited instance attributes, causing state table depletion and transit congestion.",
        "port": 1434,
        "protocol": "UDP",
        "factor": "25x",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p udp --sport 1434 -j DROP\niptables -A INPUT -p udp --dport 1434 -j DROP",
        "cisco": "access-list 101 deny udp any eq 1434 any\naccess-list 101 deny udp any any eq 1434",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip sport 1434 0xffff flowid 1:10"
    },
    "NetBIOS": {
        "mechanism": "NetBIOS Name Service (NBNS) Reflection attacks exploit Windows and Samba file-sharing hosts exposing UDP port 137 to the WAN (RFC 1002). Threat actors forge the victim IP and send a 50-byte Node Status Query using a wildcard name query (*\\x00). The target NetBIOS servers reply with extensive tables enumerating host workgroups, computer names, MAC addresses, and adapter configurations spanning several hundred bytes. This achieves an amplification factor of 4x to 5x. Traffic metrics indicate continuous UDP packets originating from port 137 with uniform byte sizes between 250 and 450 bytes, causing degradation in edge router forwarding planes.",
        "port": 137,
        "protocol": "UDP",
        "factor": "4x-5x",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p udp --sport 137 -j DROP\niptables -A INPUT -p udp --dport 137 -j DROP",
        "cisco": "access-list 101 deny udp any eq 137 any\naccess-list 101 deny udp any any eq 137",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip sport 137 0xffff flowid 1:10"
    },
    "PortMap": {
        "mechanism": "Open Network Computing Remote Procedure Call (ONC RPC) Portmapper / rpcbind reflection abuses UDP port 111 (RFC 1833). Attackers send small GetPort or Dump queries (approx. 40 bytes) with spoofed victim source IPs. The rpcbind daemon returns the full catalogue of registered RPC services (NFS, mountd, statd, ypserv) running on the host along with their port and protocol bindings. Depending on the density of installed services, amplification factors range from 7x to 28x. Telemetry demonstrates sustained high-volume UDP traffic from source port 111 with large, frequently fragmented datagrams, causing severe downstream link congestion and packet drops.",
        "port": 111,
        "protocol": "UDP",
        "factor": "7x-28x",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p udp --sport 111 -j DROP\niptables -A INPUT -p udp --dport 111 -j DROP",
        "cisco": "access-list 101 deny udp any eq 111 any\naccess-list 101 deny udp any any eq 111",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip sport 111 0xffff flowid 1:10"
    },
    "TFTP": {
        "mechanism": "Trivial File Transfer Protocol (TFTP) Amplification exploits misconfigured, publicly accessible TFTP servers running over UDP port 69 (RFC 1350). Because TFTP has no authentication or handshake mechanisms, an attacker transmits a small Read Request (RRQ) packet specifying common system files (e.g. boot.img, firmware, or config files) with the spoofed source IP of the victim. The TFTP server responds by transmitting the requested file in a sequence of 516-byte UDP datagrams to the victim. This yields an effective amplification ratio of up to 60x. Flow telemetry exhibits UDP streams originating from dynamic server ports following initial contact on port 69, characterized by repeated identical payload blocks and rapid transmission bursts.",
        "port": 69,
        "protocol": "UDP",
        "factor": "60x",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p udp --sport 69 -j DROP\niptables -A INPUT -p udp --dport 69 -j DROP",
        "cisco": "access-list 101 deny udp any eq 69 any\naccess-list 101 deny udp any any eq 69",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip sport 69 0xffff flowid 1:10"
    },
    "HTTP": {
        "mechanism": "Layer 7 HTTP Floods abuse legitimate application-layer protocols (HTTP/1.1, HTTP/2) over TCP ports 80 or 443 to exhaust web application and database infrastructure. Variants include High-Rate GET/POST Floods (Hulk, HTTP GET Flood) that generate thousands of requests with dynamic query parameters to bypass server caching, as well as Low-and-Slow attacks (Slowloris, Slowbody/R-U-Dead-Yet). Slowloris sends partial HTTP request headers ending with single '\\r\\n' instead of '\\r\\n\\r\\n' at calculated intervals, holding web server thread and worker pools open indefinitely until connection limits (MaxRequestWorkers) are reached. Slowbody transmits legitimate POST headers declaring a huge Content-Length (e.g. 4096 bytes) but streams the message body at excruciatingly slow rates (1 byte every 10-30 seconds). Both vectors exhaust application concurrency limits, connection pools, and database threads with minimal network bandwidth.",
        "port": 80,
        "protocol": "TCP",
        "factor": "N/A",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 50/s --limit-burst 100 -j ACCEPT\niptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 30 -j REJECT",
        "cisco": "ip http max-connections 50\naccess-list 101 permit tcp any host <VIP> eq 80",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dport 80 0xffff flowid 1:10"
    },
    "Zero-Day": {
        "mechanism": "Zero-Day anomalous traffic represents novel, unclassified denial-of-service vectors or multi-vector blending techniques that deviate from standard baseline distributions. Identified by unsupervised anomaly detection models (e.g. Isolation Forest) based on multi-dimensional feature space skew (extreme packet inter-arrival variance, unprecedented header flag combinations, asymmetric payload entropy, or protocol-violating packet structures). These attacks aim to bypass conventional signature-based intrusion detection systems and edge firewalls. Flow telemetry exhibits persistent deviations in multiple statistical NetFlow metrics without matching established RFC attack signatures, requiring automated sandbox inspection, dynamic rate limiting, and adaptive rule synthesis.",
        "port": 0,
        "protocol": "ANY",
        "factor": "Unknown",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -s <SRC_IP> -j DROP",
        "cisco": "access-list 101 deny ip host <SRC_IP> any",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip src <SRC_IP> flowid 1:10"
    },
    "Benign": {
        "mechanism": "Legitimate benign network traffic conforming to standard Internet Engineering Task Force (IETF) RFC protocol specifications. Exhibits full bidirectional transport-layer handshakes (complete 3-way TCP SYN, SYN-ACK, ACK cycles and proper FIN/RST terminations), natural Poisson or self-similar packet inter-arrival time distributions, balanced upload and download byte ratios, valid application-layer headers, and standard MTU payload lengths. Flow completion times reflect normal user interaction patterns, and no repetitive anomalies or spoofing traits are present. Telemetry indicates legitimate application communication suitable for immediate forwarding (XDP_PASS or ACCEPT).",
        "port": 0,
        "protocol": "ANY",
        "factor": "1x",
        "ebpf": "XDP_PASS",
        "iptables": "iptables -A INPUT -s <SRC_IP> -j ACCEPT",
        "cisco": "access-list 101 permit ip host <SRC_IP> any",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip src <SRC_IP> flowid 1:1"
    },
    "PortScan": {
        "mechanism": "Port Scanning (Reconnaissance, RFC 793, RFC 768) is a network probing technique used by adversaries or automated scanners to discover active listening services, open ports, and firewall filtering rules. Scanners transmit sequential or randomized probes across multiple destination ports (vertical scan) or across multiple subnet hosts (horizontal scan). Characteristics include single-packet or low-packet probes (fwd_pkts=1, bwd_pkts=0 or TCP RST/ICMP Port Unreachable), negligible flow duration (0.0 ms), absence of application session payloads, and rapid probing across diverse port targets. Individual probes to service ports (such as UDP port 111 or port 161) without sustained volume or handshake completion indicate port reconnaissance rather than volumetric reflection DDoS.",
        "port": 0,
        "protocol": "ANY",
        "factor": "N/A",
        "ebpf": "bpf_table_insert(blacklist_map, src_ip, ttl);",
        "iptables": "iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP\niptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP\niptables -A INPUT -m recent --name portscan --set\niptables -A INPUT -m recent --name portscan --rcheck --seconds 60 --hitcount 10 -j DROP",
        "cisco": "ip access-list extended RECON_BLOCK\ndeny ip host <SRC_IP> any\nrate-limit input 100000 1000 2000 conform-action transmit exceed-action drop",
        "tc": "tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip src <SRC_IP> flowid 1:10"
    }
}

def _resolve_entry(attack):
    key = str(attack).strip()
    if key in KNOWLEDGE:
        return KNOWLEDGE[key]
    clean_key = key.lower().replace(" ", "").replace("_", "").replace("-", "")
    for name, data in KNOWLEDGE.items():
        clean_name = name.lower().replace(" ", "").replace("_", "").replace("-", "")
        if clean_name == clean_key or clean_name in clean_key or clean_key in clean_name:
            return data
    return KNOWLEDGE["Zero-Day"]

def lookup_mechanism(attack):
    entry = _resolve_entry(attack)
    return json.dumps(entry)

def lookup_mitigation(
    attack,
    device="ebpf"
):
    entry = _resolve_entry(attack)
    dev = device.lower()
    if dev in entry:
        return entry[dev]
    return entry.get("ebpf", "")

def lookup_description(attack):
    entry = _resolve_entry(attack)
    return entry.get("mechanism", "")