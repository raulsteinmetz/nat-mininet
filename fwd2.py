#!/usr/bin/env python

from scapy.all import *
from nat_table import *

sw_hosts = 'r-eth0'
sw_servers = 'r-eth1'

nat_table = NatTable()

class PktManager:
	def get_port(pkt):
		match PktManager.get_protocol4(pkt):
			case 'TCP':
				return pkt[TCP].sport
			case 'UDP':
				return pkt[UDP].sport
			case _:
				print("Error: pkt has no valid level 4 protocol")
				return None

	def get_protocol4(pkt):
		if pkt.haslayer(TCP):
			return 'TCP'
		elif pkt.haslayer(UDP):
			return 'UDP'
		else:
			print("Error: pkt has no valid level 4 protocol")
			return None

	def gen_entry(pkt):
		src_ip = pkt[IP].src
		src_port = PktManager.get_port(pkt)
		dst_ip = pkt[IP].dst
		dst_port = pkt[TCP].dport
		protocol = PktManager.get_protocol4(pkt)

		return NatEntry(src_ip, src_port, dst_ip, dst_port, protocol)

	def get_entry(pkt):
		resp_port = PktManager.get_port(pkt)
		resp_ip = pkt[IP].src
		resp_protocol = PktManager.get_protocol4(pkt)

		return nat_table.response_translate(resp_ip, resp_port, resp_protocol)


def example(pkt):
	r_ip = '8.8.254.254'


	if pkt.sniffed_on == sw_hosts:
		print("Pacote recebido do lado privado: ")
		pkt.show()

		nat_table.add_entry(PktManager.gen_entry(pkt))
		pkt[IP].src = r_ip
		sendp(pkt, iface = sw_servers)

	elif pkt.sniffed_on == sw_servers:
		print("Pacote recebido do lado público: ")
		pkt.show()
		
		entry = PktManager.get_entry(pkt)

		if entry == None:
			print("Erro brabo: response from server has no valid entry")
			return
		
		pkt[IP].dst = entry.src_ip
		sendp(pkt, iface = sw_hosts)

	else:
		return
	
	nat_table.list_entries()
		
sniff(iface=[sw_hosts, sw_servers], filter='ip',  prn=example)