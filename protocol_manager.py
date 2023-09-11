from scapy.all import *
from scapy.layers.inet import TCP, UDP, ICMP

class L2Manager:
	def get_port_src(pkt):
		match L2Manager.get_protocol4(pkt):
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
		match L2Manager.get_protocol4(pkt):
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