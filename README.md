# Nat Implementation on mininet

Network Address Translation (NAT) is a method used in computer networking to modify network address information in Internet Protocol (IP) packet headers while they are in transit across a traffic routing device. The primary purpose of NAT is to reduce the number of public IP addresses an organization or network must use, for both economy and security purposes. It enables private network addresses to be translated to public ones, allowing multiple devices on a local network to be mapped to a single public IP address. NAT is widely used in scenarios where an organization's network must access the internet but does not require all devices within the network to have a unique global IP address. By reusing a small pool of public IP addresses, NAT effectively conserves the limited number of available public IP addresses and also adds a layer of privacy and security by hiding internal IP addresses from external networks.


## Key Commands
- **Initiate MiniNet Topology**: `sudo python3 topo.py`
- **Accessing Terminals in MiniNet**:
  - `xterm h1` for host1 terminal
  - `xterm h2` for host2 terminal
  - `xterm r` for router
  - `xterm server1` for server1 (tcp messages only)
  - `xterm server2` for server2 (udp messages only)
- **Client-Side Commands**:
  - host1: iperf -c 8.8.8.8 -p 8888 
  - host1: iperf -c 8.8.4.4 -p 8844 -u
  - host2: iperf -c 8.8.8.8 -p 8888
  - host2: iperf -c 8.8.4.4 -p 8844 -u
- **Cheking pkt behaviour**: `tcpdump` in any terminal inside the newtork topology

## Pre-Run Setup
- **Installation of Dependencies**: Ensure to use `sudo` for all `pip3` installations, as MiniNet requires superuser privileges.
  - Install `scapy` via `pip3` (sudo mode).
  - Install `mininet` using `apt`.
