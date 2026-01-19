#!/bin/bash

# --- CONFIGURATION ---
INTERFACE="enp0s1"
DEST_IP="192.168.64.4"
DEST_MAC="5A:5B:AA:E3:4A:AB" # <--- IMPORTANT: Update this!
PKT_SIZE="64"                            # 64 bytes for maximum PPS stress
COUNT="0"                                # 0 = Infinite count

# --- SETUP ---
echo "Loading pktgen module..."
modprobe pktgen

# Clear existing configuration
echo "rem_device_all" > /proc/net/pktgen/kpktgend_0

# Add the device to the kernel thread
echo "add_device $INTERFACE" > /proc/net/pktgen/kpktgend_0

# --- CONFIGURE THE DEVICE ---
echo "Configuring $INTERFACE..."
PGDEV=/proc/net/pktgen/$INTERFACE

echo "count $COUNT" > $PGDEV           # How many packets to send
echo "clone_skb 100000" > $PGDEV       # Reuse the same packet structure (faster)
echo "pkt_size $PKT_SIZE" > $PGDEV     # Packet size
echo "delay 0" > $PGDEV                # No delay (maximum speed)
echo "dst $DEST_IP" > $PGDEV           # Destination IP
echo "dst_mac $DEST_MAC" > $PGDEV      # Destination MAC

# --- START TRAFFIC ---
echo "Starting packet generation..."
echo "start" > /proc/net/pktgen/pgctrl

echo "Done! Traffic is flowing. Press Ctrl+C to stop monitoring."

# --- MONITORING ---
# Watch the stats in real-time
watch -n 1 "cat /proc/net/pktgen/$INTERFACE"