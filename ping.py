#!/usr/bin/env python

from scapy.all import *

p = srp1(Ether()/IP(dst="10.2.2.1")/ICMP(),iface='r-eth2')

p.show()