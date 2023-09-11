#!/usr/bin/env python

from scapy.all import *

def example(pkt):
        pkt[IP].show()

sniff(iface='r-eth1', prn=example)