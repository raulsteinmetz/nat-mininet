#!/usr/bin/env python

from scapy.all import *

def example(pkt):
	pkt.show()
	if pkt.sniffed_on == 'r-eth1' and pkt[IP].dst == '10.2.2.1':
		pkt[Ether].dst = None
		sendp(pkt, iface='r-eth2')
	elif pkt.sniffed_on == 'r-eth2' and pkt[IP].dst == '10.1.1.1':
		pkt[Ether].dst = None
		sendp(pkt, iface='r-eth1')
	else:
		return
		
sniff(iface=["r-eth1","r-eth2"], filter='ip',  prn=example)