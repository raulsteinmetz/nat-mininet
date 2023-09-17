#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from nat_table import *
from protocol_manager import L4Manager


		
def main():
	internal_interface = 'r-eth0'
	public_interface = 'r-eth1'

	nat_table = NatTable()

	def nat_gen_entry(pkt):
		ip_src = pkt[IP].src
		port_src = L4Manager.get_port_src(pkt)
		ip_dest = pkt[IP].dst
		port_dst = L4Manager.get_port_dst(pkt)
		protocol = L4Manager.get_protocol4(pkt)

		return TableEntry(ip_src, port_src, ip_dest, port_dst, protocol)

	def supported(pkt: Packet):
		return L4Manager.get_protocol4(pkt) != None

	def nat_find_entry(pkt):
		port_scr = L4Manager.get_port_src(pkt)
		port_dst = L4Manager.get_port_dst(pkt)
		return nat_table.find_entry(port_scr, port_dst)

	def mac(interface):
		return get_if_hwaddr(interface)
	
	def ip(interface):
		return get_if_addr(interface)

	def sent(pkt):
		if pkt[Ether].src == mac(pkt.sniffed_on):
			return True
		return False

	def checksum_recalc(pkt):
		del pkt[IP].chksum
		del pkt[IP].payload.chksum
		return pkt.__class__(bytes(pkt))

	def update_ips(pkt, src=None, dst=None):
		pkt = pkt.copy()

		if src is None:
			src = pkt[IP].src
		if dst is None:
			dst = pkt[IP].dst

		pkt[IP].src = src
		pkt[IP].dst = dst

		pkt[IP].ttl = pkt[IP].ttl - 1

		pkt[Ether].src = None
		pkt[Ether].dst = None
		return checksum_recalc(pkt)

	def handle_private(pkt):
		entry = nat_gen_entry(pkt)
		nat_table.add_entry(entry)
		print(entry.protocol)
		new = update_ips(pkt, src = ip(public_interface))
		print(new[IP].src)
		sendp(new, iface = public_interface)
		return new

	def handle_public(pkt):
		entry = nat_find_entry(pkt)
		if entry:
			new = update_ips(pkt, dst = entry.ip_src)
			sendp(new, iface = internal_interface)
			return new
		return None

	def router(pkt):
		if not supported(pkt):
			return

		if sent(pkt):
			return

		if pkt.sniffed_on == internal_interface:
			pkt = handle_private(pkt)
		elif pkt.sniffed_on == public_interface:
			pkt = handle_public(pkt)

		#pkt.show()

	sniff(iface=[internal_interface, public_interface], filter='ip', prn=router)

if __name__ == '__main__':
	main()
