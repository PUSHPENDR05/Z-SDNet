from mininet.topo import Topo

class SimpleTopo(Topo):
    def build(self):
        # 2 Hosts (वर्चुअल कंप्यूटर)
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        # 1 Switch (वर्चुअल स्विच)
        s1 = self.addSwitch('s1')
        # Links (तार जोड़ना)
        self.addLink(h1, s1)
        self.addLink(h2, s1)

topos = { 'mytopo': (lambda: SimpleTopo()) }
