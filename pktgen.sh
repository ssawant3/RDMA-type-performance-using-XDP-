#!/bin/bash

# --- CONFIGURATION ---
INTERFACE="enp0s1"
DEST_IP="192.168.64.4"
DEST_MAC="5A:5B:AA:E3:4A:AB" 
PKT_SIZE="512"                            
COUNT="0"                 # 0 = Infinite (Use Ctrl+C to stop)

# UDP PORT SETTINGS (Both locked to 5201)
UDP_SRC_MIN=5201        # <--- CHANGED: Locked to 5201
UDP_SRC_MAX=5201        # <--- CHANGED: Locked to 5201
UDP_DST_MIN=5201
UDP_DST_MAX=5201

# --- TRAP FUNCTION ---
cleanup() {
    echo ""
    echo "!!! Ctrl+C Detected !!!"
    echo "Stopping packet generation..."
    echo "stop" > /proc/net/pktgen/pgctrl
    echo "Traffic stopped successfully."
    exit 0
}

# Register the trap
trap cleanup SIGINT

# --- SETUP ---
echo "Loading pktgen module..."
modprobe pktgen

# Clear existing configuration
echo "rem_device_all" > /proc/net/pktgen/kpktgend_0
echo "add_device $INTERFACE" > /proc/net/pktgen/kpktgend_0

# --- CONFIGURE THE DEVICE ---
echo "Configuring $INTERFACE..."
PGDEV=/proc/net/pktgen/$INTERFACE

echo "count $COUNT" > $PGDEV           
echo "clone_skb 100000" > $PGDEV       
echo "pkt_size $PKT_SIZE" > $PGDEV     
echo "delay 0" > $PGDEV                
echo "dst $DEST_IP" > $PGDEV           
echo "dst_mac $DEST_MAC" > $PGDEV      

# Set UDP Ports
echo "udp_src_min $UDP_SRC_MIN" > $PGDEV
echo "udp_src_max $UDP_SRC_MAX" > $PGDEV
echo "udp_dst_min $UDP_DST_MIN" > $PGDEV
echo "udp_dst_max $UDP_DST_MAX" > $PGDEV

# --- START TRAFFIC ---
echo "Starting packet generation..."
echo "start" > /proc/net/pktgen/pgctrl
echo "Traffic is flowing. Press Ctrl+C to stop and exit."

# --- MONITORING LOOP ---
while true; do
    echo "--- Pktgen Status (Press Ctrl+C to Stop) ---"
    cat /proc/net/pktgen/$INTERFACE
    sleep 1
done