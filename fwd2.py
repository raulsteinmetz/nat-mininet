#!/usr/bin/env python

from scapy.all import *

sw_hosts = 'r-eth0'
sw_servers = 'r-eth1'

r_ip_server = '8.8.254.254'
r_ip_host = '10.1.1.254'

def example(pkt):
	# debug
	# pkt.show()

	if pkt.sniffed_on == sw_hosts:
		print("\n\n\n\nRecebido do Host:")
		pkt.show()
		pkt[IP].src = r_ip_server
		pkt.show()
		sendp(pkt, iface=sw_servers)

	elif pkt.sniffed_on == sw_servers:
		print("\n\n\n\nRecebido do Server:")

		pkt.show()
		pkt[IP].dst = "10.1.1.1"
		pkt[IP].src = None
		pkt.show()
		sendp(pkt, iface=sw_hosts)
	else:
		return
		
sniff(iface=[sw_hosts, sw_servers], filter='ip',  prn=example)