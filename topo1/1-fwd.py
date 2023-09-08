#!/usr/bin/env python

from scapy.all import *

def example(pkt):

	if pkt.sniffed_on == 'r-eth1' and pkt[IP].dst == '10.2.2.1':
		print("\n\n\nRecebido do host1")
		pkt.show()
		pkt[Ether].dst = None
		pkt.show()
		sendp(pkt, iface='r-eth2') # envia pra porta do h2
	elif pkt.sniffed_on == 'r-eth2' and pkt[IP].dst == '10.1.1.1':
		print("\n\n\nRecebido do host2")
		pkt.show()
		pkt[Ether].dst = None
		pkt.show()
		sendp(pkt, iface='r-eth1')
	else:
		return
		
sniff(iface=["r-eth1","r-eth2"], filter='ip',  prn=example)