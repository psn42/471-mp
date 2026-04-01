from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time

def tor_network():
    net = Mininet(controller=Controller, switch=OVSKernelSwitch)
    net.addController('c0')
    s1 = net.addSwitch('s1')

    info('Adding Hosts & Relays\n')
    client = net.addHost('client', ip='10.0.0.100')
    r1 = net.addHost('r1', ip='10.0.0.1')
    r2 = net.addHost('r2', ip='10.0.0.2')
    r3 = net.addHost('r3', ip='10.0.0.3')
    server = net.addHost('server', ip='10.0.0.200')

    info('Creating Links\n')
    for node in [client, r1, r2, r3, server]:
        net.addLink(node, s1)

    info('Starting Network\n')
    net.start()

    info('Launching Tor Relays\n')
    r1.cmd('python3 SimpleTor_relay.py 9001 > r1_log.txt 2>&1 &')
    r2.cmd('python3 SimpleTor_relay.py 9001 > r2_log.txt 2>&1 &')
    r3.cmd('python3 SimpleTor_relay.py 9001 > r3_log.txt 2>&1 &')
    
    time.sleep(1) 

    info('Network Ready. Entering CLI...\n')
    CLI(net)

    info('Stopping Network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    tor_network()