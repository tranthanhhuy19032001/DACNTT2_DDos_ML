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

        # Add network infrastructure nodes (routers)
        for hname, mac, ip, route in hosts:
            self.addHost(hname, cpu=1.0/20, mac=mac, ip=ip, defaultRoute=f'via {route}')

        # Add network infrastructure nodes
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

# Function to generate traffic in the network
def generate_traffic(hosts):
    h1 = hosts[0]
    
    print("--------------------------------------------------------------------------------")    
    print("Start generating traffic ...")    
    h1.cmd('cd /home/mininet/webserver')
    h1.cmd('python -m SimpleHTTPServer 80 &') # Start HTTP server on h1
    h1.cmd('iperf -s -p 5050 &') # Start TCP iperf server on h1
    h1.cmd('iperf -s -u -p 5051 &') # Start UDP iperf server on h1
    sleep(10)

    for h in hosts:
        h.cmd('cd /home/mininet/Downloads')
    
    for i in range(100):
        print("--------------------------------------------------------------------------------")    
        print(f"Loop {i+1} ...")    
        print("--------------------------------------------------------------------------------")
        
        for j in range(10):
            src = choice(hosts)
            dst = choose_ip_destination()
            
            print(f"Generating ICMP traffic between {src} and {dst} and TCP/UDP traffic between {src} and h1")
            src.cmd(f"ping {dst} -c 100 {'&' if j < 9 else ''}") # Generate ICMP traffic
            src.cmd("iperf -p 5050 -c 192.168.0.1") # Generate TCP traffic
            src.cmd("iperf -p 5051 -u -c 192.168.0.1") # Generate UDP traffic
            
            print(f"{src} Downloading index.html from h1")
            src.cmd("wget http://192.168.0.1/index.html") # Download index.html from h1
            print(f"{src} Downloading test.zip from h1")
            src.cmd("wget http://192.168.0.1/test.zip") # Download test.zip from h1
         
        h1.cmd("rm -f *.* /home/mininet/Downloads") # Clean up downloaded files
    
    print("--------------------------------------------------------------------------------")
    print("End generating traffic!")

def startNetwork():
    # Create the custom topology
    topo = MyTopology()
    
    # Define the remote controller with its IP and port
    ryu_controller = RemoteController('ryu_controller', ip='192.168.56.104', port=6653)
    
     # Initialize the Mininet network with the custom topology and traffic control links
    net = Mininet(topo=topo, link=TCLink, controller=ryu_controller)
    
    # Start the network
    net.start()
    
    # Configure the network settings
    configure_network(net)

    # Retrieve the hosts from the network
    hosts = [net.get(hname) for hname in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'attacker']]

    # Generate traffic in the network
    generate_traffic(hosts)
    
    # Stop the network
    net.stop()

# Main function to set log level and start the network
if __name__ == '__main__':
    start = datetime.now()
    setLogLevel('info')
    startNetwork()
    end = datetime.now()
    print(f"Execution time: {end - start}")
