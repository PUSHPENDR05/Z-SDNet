from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class ZSDNetTopo(Topo):
    def build(self):
        # 3 Hosts add kiye
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')

        # OpenFlow 1.3 Switch add kiya
        s1 = self.addSwitch('s1', protocols='OpenFlow13')

        # Links connect kiye
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

def run():
    topo = ZSDNetTopo()
    # Remote Ryu Controller (port 6653)
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        autoSetMacs=True
    )
    net.start()
    info('*** Network Started. Starting CLI:\n')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
