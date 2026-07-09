#!/bin/bash
set -e

echo "[+] =================================================================="
echo "[+] SETUP VM1 (GATEWAY / ML-IPS / eBPF DATA PLANE)"
echo "[+] =================================================================="

# 1. Cập nhật hệ thống và cài đặt các công cụ hỗ trợ debug mạng
echo "[+] 1. Cập nhật hệ thống và cài tiện ích cơ bản..."
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y git curl wget build-essential iptables-persistent netfilter-persistent tcpdump htop nload

# 2. Cài đặt bộ công cụ biên dịch eBPF / BCC (Kernel Space)
echo "[+] 2. Cài đặt môi trường biên dịch eBPF / BCC..."
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc libbpf-dev clang llvm

# 3. Cài đặt Python 3, PIP và các thư viện Machine Learning / Networking
echo "[+] 3. Cài đặt Python PIP và thư viện AI / Networking..."
sudo apt-get install -y python3-pip python3-dev
sudo pip3 install --upgrade pip
sudo pip3 install nfstream google-cloud-storage requests numpy pandas scikit-learn imbalanced-learn xgboost joblib

# 4. Tối ưu hóa cấu hình Linux Kernel (Bật IP Forward & Chống SYN Flood)
echo "[+] 4. Cấu hình Linux Kernel (sysctl)..."
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.default.rp_filter=1
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65536

# Lưu cấu hình sysctl
cat << 'SYSCTL_EOF' | sudo tee /etc/sysctl.d/99-ddos-mitigation.conf
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=65536
SYSCTL_EOF

# 5. Thiết lập luật định tuyến NAT
echo "[+] 5. Thiết lập luật định tuyến NAT..."

sudo iptables -t nat -F
sudo iptables -t nat -A PREROUTING -d 10.99.99.99 -j DNAT --to-destination 10.240.0.2
sudo iptables -t nat -A POSTROUTING -d 10.240.0.2 -j MASQUERADE

sudo netfilter-persistent save

echo "[+] =================================================================="
echo "[+] SETUP VM1 COMPLETED"
echo "[+] =================================================================="