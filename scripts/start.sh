#!/bin/bash

# Start the Gatekeeper service

# Stop immediately when any command fails
set -e


# Set project paths and network interface
PROJECT_ROOT="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
    pwd
)"

SRC_DIR="${PROJECT_ROOT}/src"

INTERFACE="${GW_INTERFACE:-ens4}"


# Check whether the script is running as root
if [ "$EUID" -ne 0 ]; then
    echo "[-] This script must run as root."
    echo "[-] eBPF/XDP requires CAP_SYS_ADMIN."
    echo "[-] Try again with: sudo $0"
    exit 1
fi


# Check whether the trained model exists
MODEL_FILE="${PROJECT_ROOT}/models/binary.pkl"

if [ ! -f "${MODEL_FILE}" ]; then
    echo "[-] Model file not found:"
    echo "    ${MODEL_FILE}"

    echo "[-] Run the following commands first:"
    echo "    python3 src/parser.py"
    echo "    python3 src/trainer.py"

    exit 1
fi


# Start the Gatekeeper service
echo "[*] Starting Gatekeeper"
echo "[*] Interface: ${INTERFACE}"


# Move to the source directory
cd "${SRC_DIR}"


# Replace the shell process with Gatekeeper
exec python3 gatekeeper.py \
    --interface "${INTERFACE}"