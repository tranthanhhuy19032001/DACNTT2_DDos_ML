from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController, Node
from time import sleep
from datetime import datetime
from random import choice

# Define a custom switch class with a specific OVS version
class MyOVSKernelSwitch(OVSKernelSwitch):
    OVSVersion = "2.13.8"

# Custom Topology Class
class MyTopology(Topo):
    def build(self):
        # Add switches with specific configurations
        s1 = self.addSwitch('s1', cls=MyOVSKernelSwitch, protocols='OpenFlow13', dpid='0000000000000001')
        s2 = self.addSwitch('s2', cls=MyOVSKernelSwitch, protocols='OpenFlow13', dpid='0000000000000002')
        
        # Add hosts with the specified attributes
        hosts = [
            ('h1', '00:00:00:00:00:01', '192.168.0.1/24', '192.168.0.254'),
            ('h2', '00:00:00:00:00:02', '192.168.0.2/24', '192.168.0.254'),
            ('h3', '00:00:00:00:00:03', '192.168.0.3/24', '192.168.0.254'),
            ('h4', '00:00:00:00:00:04', '192.168.1.4/24', '192.168.1.254'),
            ('h5', '00:00:00:00:00:05', '192.168.1.5/24', '192.168.1.254'),
            ('h6', '00:00:00:00:00:06', '192.168.1.6/24', '192.168.1.254'),
            ('attacker', '00:00:00:00:00:07', '10.0.2.100/24', '10.0.2.1')
        ]
        # Config ip, mac address and routing for devices
        for hname, mac, ip, route in hosts:
            self.addHost(hname, cpu=1.0/20, mac=mac, ip=ip, defaultRoute=f'via {route}')

        # Add network infrastructure nodes (routers)
        R1 = self.addNode('R1', cls=Node)
        ISP = self.addNode('ISP', cls=Node)

        # Add links between devices
        self.addLink('h1', s1)
        self.addLink('h2', s1)
        self.addLink('h3', s1)
        self.addLink('h4', s2)
        self.addLink('h5', s2)
        self.addLink('h6', s2)
        self.addLink(s1, R1)
        self.addLink(s2, R1)
        self.addLink(R1, ISP)
        self.addLink('attacker', ISP)

# Configure the network settings for the routers
def configure_network(net):
    # Get routers from the network
    R1 = net.getNodeByName('R1')
    ISP = net.getNodeByName('ISP')

    # Enable IP forwarding on both routers
    R1.cmd('sysctl -w net.ipv4.ip_forward=1')
    ISP.cmd('sysctl -w net.ipv4.ip_forward=1')

    # Configure interfaces and routes for R1
    R1.cmd('ifconfig R1-eth0 192.168.0.254 netmask 255.255.255.0')
    R1.cmd('ifconfig R1-eth1 192.168.1.254 netmask 255.255.255.0')
    R1.cmd('ifconfig R1-eth2 10.0.1.1 netmask 255.255.255.0')
    R1.cmd('ip route add 192.168.0.0/24 dev R1-eth0')
    R1.cmd('ip route add 192.168.1.0/24 dev R1-eth1')
    R1.cmd('ip route add 0.0.0.0/0 via 10.0.1.2')

    # Configure interfaces and routes for ISP
    ISP.cmd('ifconfig ISP-eth0 10.0.1.2 netmask 255.255.255.0')
    ISP.cmd('ifconfig ISP-eth1 10.0.2.1 netmask 255.255.255.0')
    ISP.cmd('ip route add 192.168.0.0/24 via 10.0.1.1')
    ISP.cmd('ip route add 192.168.1.0/24 via 10.0.1.1')
    ISP.cmd('ip route add 0.0.0.0/0 via 10.0.1.1')

# Choose a random IP destination from a predefined list
def choose_ip_destination():
    ip_list = [
        "192.168.0.1",
        "192.168.0.2",
        "192.168.0.3",
        "192.168.1.4",
        "192.168.1.5",
        "192.168.1.6"
    ]
    return choice(ip_list)

# Execute a specific attack from source to destination
def execute_attack(src, dst, attack_cmd, description, duration=20):
    print("--------------------------------------------------------------------------------")
    print(description)
    print("--------------------------------------------------------------------------------")
    src.cmd(f"timeout {duration}s {attack_cmd} {dst}")
    sleep(100)
    print(f"End {description}")

# Start the network and execute attacks
def startNetwork():
    # Create the custom topology
    topo = MyTopology()

    # Define the remote controller with its IP and port
    ryu_controller = RemoteController('ryu_controller', ip='192.168.56.104', port=6653)
    
    # Initialize the Mininet network with the custom topology and traffic control links
    net = Mininet(topo=topo, link=TCLink, controller=ryu_controller)
    net.start()
    
    # Configure the network settings
    configure_network(net)

    # Retrieve the hosts from the network
    hosts = [net.get(hname) for hname in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'attacker']]
    
    # Set up a simple HTTP server on host h1
    h1 = net.get('h1')
    h1.cmd('cd /home/mininet/webserver')
    h1.cmd('python -m SimpleHTTPServer 80 &')
    
    # Execute an ICMP (Ping) Flood attack
    execute_attack(choice(hosts), choose_ip_destination(), "hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood", "Executing an ICMP (Ping) Flood attack")
    # Execute an UDP Flood attack
    execute_attack(choice(hosts), choose_ip_destination(), "hping3 -2 -V -d 120 -w 64 --rand-source --flood", "Executing an UDP Flood attack")
    # Choose a random destination for the LAND attack
    dst = choose_ip_destination()
    execute_attack(choice(hosts), dst, f"hping3 -1 -V -d 120 -w 64 --flood -a {dst}", "Executing a LAND Attack")
    # Execute a TCP-SYN Flood attack to host h1 192.168.0.1
    execute_attack(choice(hosts), "192.168.0.1", "hping3 -S -V -d 22617 -w 64 -p 80 --rand-source --flood", "Executing a TCP-SYN Flood attack to host h1 192.168.0.1")

    net.stop()

# Main function to set log level and start the network
if __name__ == '__main__':
    start = datetime.now()
    setLogLevel('info')
    startNetwork()
    end = datetime.now()
    print(f"Execution time: {end - start}")
