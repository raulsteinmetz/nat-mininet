#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from nat_table import *
from protocol_manager import L2Manager

internal_interface = 'r-eth0'
public_interface = 'r-eth1'

nat_table = NatTable()

		
def main():

	def nat_gen_entry(pkt):
		ip_src = pkt[IP].src
		port_src = L2Manager.get_port_src(pkt)
		ip_dest = pkt[IP].dst
		port_dst = L2Manager.get_port_dst(pkt)
		protocol = L2Manager.get_protocol4(pkt)

		if port_src == None or port_dst == None:
			exit()

		return TableEntry(ip_src, port_src, ip_dest, port_dst, protocol)

	def nat_find_entry(pkt):
		port_scr = L2Manager.get_port_src(pkt)
		port_dst = L2Manager.get_port_dst(pkt)

		return nat_table.find_entry(port_scr, port_dst)


	def mac(interface):
		return get_if_hwaddr(interface)

	def we_send_it(pkt):
		return pkt[Ether].src == mac(pkt.sniffed_on)


	def checksum_recalc(pkt):
		return pkt.__class__(bytes(pkt))

	def update_ttl(pkt):
		pkt = pkt.copy()
		pkt[IP].ttl = pkt[IP].ttl - 1
		return pkt

	def update_ips(pkt, src=None, dst=None):
		pkt = pkt.copy()

		if src is None:
			src = pkt[IP].src
		if dst is None:
			dst = pkt[IP].dst

		pkt[IP].src = src
		pkt[IP].dst = dst

		pkt = update_ttl(pkt)

		del pkt[Ether].dst
		del pkt[Ether].src
		del pkt[IP].chksum
		del pkt[IP].payload.chksum
		if(L2Manager.get_protocol4(pkt) == 'ICMP'):
			del pkt[ICMP].chksum
		
		return checksum_recalc(pkt)

	def ip(interface):
		return get_if_addr(interface)
	
	def handle_private(pkt):
		if pkt.sniffed_on == internal_interface:
			print("Pacote recebido do lado privado: ")
			pkt.show()
			nat_table.add_entry(nat_gen_entry(pkt))
			pkt = update_ips(pkt, src = ip(public_interface))
			
			pkt.show()

			sendp(pkt, iface = public_interface)

	def handle_public(pkt):
		if pkt.sniffed_on == public_interface:
			print("Pacote recebido do lado público: ")
			pkt.show()
			
			entry = nat_find_entry(pkt)

			if entry == None:
				print("Erro brabo: response from server has no valid entry")
				return
			
			pkt = update_ips(pkt, dst = entry.ip_src)

			pkt.show()

			sendp(pkt, iface = internal_interface)

	def router(pkt):
		if we_send_it(pkt):
			return
		
		handle_private(pkt)
		handle_public(pkt)
		
		nat_table.list_entries()
			
	sniff(iface=[internal_interface, public_interface], filter='ip',  prn=router)

if __name__ == '__main__':
    main()
