from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.topo import Topo
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class BasicTopo(Topo):
    def build(self, **_opts):
        sw1 = self.addSwitch('sw1', cls=OVSBridge)
        sw2 = self.addSwitch('sw2', cls=OVSBridge)
        
        router = self.addHost('r', ip=None)
        host1 = self.addHost('h1', ip='10.1.1.1/24', defaultRoute='via 10.1.1.254')
        host2 = self.addHost('h2', ip='10.1.1.2/24', defaultRoute='via 10.1.1.254')
        
        server1 = self.addHost('server1', ip='8.8.8.8/16', defaultRoute='via 8.8.254.254')
        server2 = self.addHost('server2', ip='8.8.4.4/16', defaultRoute='via 8.8.254.254')
        		      
        self.addLink(host1, sw1)
        self.addLink(host2, sw1)
        self.addLink(sw1, router, intfName2='r-eth0',params2={'ip':'10.1.1.254/24'})

        self.addLink(server1, sw2)
        self.addLink(server2, sw2)
        self.addLink(sw2, router, intfName2='r-eth1', params2={'ip':'8.8.254.254/16'})
    
def run():
    "Trabalho 2: NAT"
    net = Mininet(topo=BasicTopo(), controller=None)
    net.get('server1').cmd('iperf -s -p 8888 &')
    net.get('server2').cmd('iperf -s -u -p 8844 &')
        
    for _, v in net.nameToNode.items():
     for itf in v.intfList():
      v.cmd('ethtool -K '+itf.name+' tx off rx off') 
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()