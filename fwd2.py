#!/usr/bin/env python

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from nat_table import *

internal_interface = 'r-eth0'
public_interface = 'r-eth1'

nat_table = NatTable()

class PktManager:
	def get_port_src(pkt):
		match PktManager.get_protocol4(pkt):
			case 'TCP':
				return pkt[TCP].sport
			case 'UDP':
				return pkt[UDP].sport
			case 'ICMP':
				return pkt[ICMP].id
			case _:
				print("Error: pkt has no valid level 4 protocol")
				return None
			
	def get_port_dst(pkt):
		match PktManager.get_protocol4(pkt):
			case 'TCP':
				return pkt[TCP].dport
			case 'UDP':
				return pkt[UDP].dport
			case 'ICMP':
				return pkt[ICMP].id
			case _:
				print("Error: pkt has no valid level 4 protocol")
				return None


	def get_protocol4(pkt):
		if pkt.haslayer(TCP):
			return 'TCP'
		elif pkt.haslayer(UDP):
			return 'UDP'
		elif pkt.haslayer(ICMP):
			return 'ICMP'
		else:
			print("Error: pkt has no valid level 4 protocol")
			return None

def nat_gen_entry(pkt):
	ip_src = pkt[IP].src
	port_src = PktManager.get_port_src(pkt)
	ip_dest = pkt[IP].dst
	port_dst = PktManager.get_port_dst(pkt)
	protocol = PktManager.get_protocol4(pkt)

	if port_src == None or port_dst == None:
		exit()

	return TableEntry(ip_src, port_src, ip_dest, port_dst, protocol)

def nat_find_entry(pkt):
	port_scr = PktManager.get_port_src(pkt)
	port_dst = PktManager.get_port_dst(pkt)

	return nat_table.find_entry(port_scr, port_dst)


def mac(interface):
	return get_if_hwaddr(interface)

def we_send_it(pkt):
	if pkt[Ether].src == mac(pkt.sniffed_on):
		return True
	return False

def checksum_recalc(pkt):
	del pkt[IP].chksum
	del pkt[IP].payload.chksum

	if(PktManager.get_protocol4(pkt) == 'ICMP'):
		del pkt[ICMP].chksum

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

	pkt[Ether].dst = None
	pkt[Ether].src = None
	return checksum_recalc(pkt)

def ip(interface):
	return get_if_addr(interface)

def example(pkt):

	if we_send_it(pkt):
		return

	if pkt.sniffed_on == internal_interface:
		print("Pacote recebido do lado privado: ")
		pkt.show()

		nat_table.add_entry(nat_gen_entry(pkt))

		pkt = update_ips(pkt, src = ip(public_interface))
		
		pkt.show()

		sendp(pkt, iface = public_interface)

	elif pkt.sniffed_on == public_interface:
		print("Pacote recebido do lado público: ")
		pkt.show()
		
		entry = nat_find_entry(pkt)

		if entry == None:
			print("Erro brabo: response from server has no valid entry")
			return
		
		pkt = update_ips(pkt, dst = entry.ip_src)

		pkt.show()

		sendp(pkt, iface = internal_interface)
	else:
		return
	
	nat_table.list_entries()
		
sniff(iface=[internal_interface, public_interface], filter='ip',  prn=example)