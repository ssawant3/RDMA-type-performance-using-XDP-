#!/bin/bash

# --- CONFIGURATION ---
INTERFACE="enp0s1"
XDPOBJ="xdp_tx.o"
CFILE="xdp_tx.c"

# The Rule to Install:
# "Block packets COMING FROM this IP, destined for UDP Port 5201"
SENDER_IP="192.168.64.5"   # <--- REPLACE THIS WITH YOUR CLIENT/SENDER IP!
TARGET_PORT="5201"         # The destination port to block
PROTOCOL="17"              # 17 = UDP

# --- 1. COMPILE ---
echo "Compiling XDP program..."
clang -O2 -g -target bpf \
  -I/usr/include/aarch64-linux-gnu \
  -D__TARGET_ARCH_arm64 \
  -c $CFILE -o $XDPOBJ


if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

# --- 2. LOAD XDP ---
echo "Loading XDP program on $INTERFACE..."
# Unload anything existing first (optional, but safe)
sudo ip link set dev $INTERFACE xdp off
# Load the new object
sudo ip link set dev $INTERFACE xdp obj $XDPOBJ sec xdp

if [ $? -ne 0 ]; then
    echo "Failed to load XDP program. Do you have root privileges?"
    exit 1
fi

echo "XDP Program loaded successfully."

# --- 3. GET MAP IDs ---
# We use bpftool to find the ID of the maps we just loaded
PROTO_MAP_ID=$( sudo bpftool map show | grep "block_proto_map" | awk -F: '{print $1}')
CONFIG_MAP_ID=$(sudo bpftool map show | grep "block_config_ma" | awk -F: '{print $1}')

if [ -z "$PROTO_MAP_ID" ] || [ -z "$CONFIG_MAP_ID" ]; then
    echo "Could not find maps. Is bpftool installed? (sudo apt install linux-tools-common linux-tools-generic)"
    exit 1
fi

echo "Found Maps - Proto_Map_ID: $PROTO_MAP_ID, Config_Map_ID: $CONFIG_MAP_ID"

# --- 4. POPULATE PROTOCOL MAP (Global Switch) ---
# Key: 0 (Index 0) -> Value: 17 (UDP)
# Hex: 17 = 0x11
echo "Setting Protocol Filter to UDP (17)..."
sudo bpftool map update id $PROTO_MAP_ID key hex 00 00 00 00 value hex 11

# --- 5. POPULATE CONFIG MAP (The Specific Rule) ---
# Logic: Key = Source IP, Value = Dest Port

# Helper: Convert IP to Hex Bytes (Network Byte Order)
# 192.168.64.5 -> "C0 A8 40 05"
IFS='.' read -r -a IP_PARTS <<< "$SENDER_IP"
IP_HEX=$(printf "%02X %02X %02X %02X" ${IP_PARTS[0]} ${IP_PARTS[1]} ${IP_PARTS[2]} ${IP_PARTS[3]})

# Helper: Convert Port to Hex Bytes (Little Endian for User Space Value)
# 5201 -> 0x1451 -> "51 14 00 00" (since value is u32)
P_HEX=$(printf "%04X" $TARGET_PORT)
# Flip to Little Endian for bpftool input
P_LOW=${P_HEX:2:2}
P_HIGH=${P_HEX:0:2}
PORT_VAL_HEX="$P_LOW $P_HIGH 00 00"

echo "Blocking Source IP: $SENDER_IP targeting Port: $TARGET_PORT"
echo "  - IP Hex (Key): $IP_HEX"
echo "  - Port Hex (Value): $PORT_VAL_HEX"

sudo bpftool map update id $CONFIG_MAP_ID \
    key hex $IP_HEX \
    value hex $PORT_VAL_HEX

echo "-----------------------------------------------------"
echo "Done! XDP is filtering."
echo "Packets from $SENDER_IP to UDP port $TARGET_PORT will be DROPPED."
echo "Check drops with: sudo bpftool prog show"