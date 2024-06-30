from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, arp, ethernet, ether_types, in_proto, ipv4, icmp, tcp, udp

# Global variable for flow serial number
FLOW_SERIAL_NO = 0

def get_flow_number():
    """Increment and return a unique flow number."""
    global FLOW_SERIAL_NO
    FLOW_SERIAL_NO += 1
    return FLOW_SERIAL_NO

class SimpleSwitch13(app_manager.RyuApp):
    """A simple switch implementation using Ryu framework and OpenFlow 1.3."""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # Dictionary to map MAC addresses to ports
        self.mitigation_flag = 0  # Flag for mitigation
        self.arp_ip_to_port = {}  # Dictionary to map ARP IP addresses to ports
        self.ip_to_mac = {}  # Dictionary to map IP addresses to MAC addresses
        self.port_need_to_block = 0
        self.blocked_ports = []
        #print("Init of SWITCH")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install a default flow entry to send unmatched packets to the controller."""
        #print("switch_features_handler of SWITCH")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        flow_serial_no = get_flow_number()
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        
        self.add_flow(datapath, 0, match, actions, flow_serial_no)

    def add_flow(self, datapath, priority, match, actions, serial_no, buffer_id=None, idle=0, hard=0):
        """Add a flow entry to the switch."""
        #print("add_flow of SWITCH")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=serial_no, buffer_id=buffer_id,
                                    idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=serial_no, priority=priority,
                                    idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        

    def block_port(self, datapath, portnumber):
        """Block a specific port on the switch."""
        #print("block_port of SWITCH")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=portnumber)
        actions = []
        flow_serial_no = get_flow_number()
        self.add_flow(datapath, priority=100, match=match, actions=actions, serial_no=flow_serial_no, hard=0)
        self.blocked_ports.append(portnumber)
        #self.logger.info(f"Blocked port {portnumber} on switch {datapath.id}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle incoming packets and decide how to forward them."""
        #print("_packet_in_handler of SWITCH")
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.arp_ip_to_port.setdefault(dpid, {})
        self.arp_ip_to_port[dpid].setdefault(in_port, [])

        # Learn a MAC address to avoid flooding next time.
        self.mac_to_port[dpid][src] = in_port

        # Learn IP to MAC mapping
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            self.ip_to_mac[arp_pkt.src_ip] = src

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            self.ip_to_mac[ip_pkt.src] = src
            ip_dst = ip_pkt.dst
            if ip_pkt.proto == in_proto.IPPROTO_ICMP:
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    #self.logger.info("ICMP request packet destined to %s received on port %d", ip_dst, in_port)
                    if ip_dst in self.ip_to_mac:
                        if self.ip_to_mac[ip_dst] in self.mac_to_port[dpid]:
                            self.port_need_to_block = self.mac_to_port[dpid][self.ip_to_mac[ip_dst]]
                            #self.logger.info("Port connecting to %s: %d", ip_dst, self.port_need_to_block)
                            
                        #else:
                        #    self.logger.warning("MAC %s not found in mac_to_port mapping", self.ip_to_mac[ip_dst])
                    #else:
                    #    self.logger.warning("IP %s not found in ip_to_mac mapping", ip_dst)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        
        # If ARP request packet, log the IP and MAC address from that port
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt.opcode == arp.ARP_REQUEST or arp_pkt.opcode == arp.ARP_REPLY:
                if arp_pkt.src_ip not in self.arp_ip_to_port[dpid][in_port]:
                    self.arp_ip_to_port[dpid][in_port].append(arp_pkt.src_ip)

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # Check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst
                protocol = ip_pkt.proto

                if protocol == in_proto.IPPROTO_ICMP:
                    icmp_pkt = pkt.get_protocol(icmp.icmp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=src_ip, ipv4_dst=dst_ip,
                                            ip_proto=protocol, icmpv4_code=icmp_pkt.code,
                                            icmpv4_type=icmp_pkt.type)
                elif protocol == in_proto.IPPROTO_TCP:
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=src_ip, ipv4_dst=dst_ip,
                                            ip_proto=protocol,
                                            tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port)
                elif protocol == in_proto.IPPROTO_UDP:
                    udp_pkt = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=src_ip, ipv4_dst=dst_ip,
                                            ip_proto=protocol,
                                            udp_src=udp_pkt.src_port, udp_dst=udp_pkt.dst_port)
                if self.mitigation_flag:
                    if src_ip not in self.arp_ip_to_port[dpid][in_port]:
                        if self.port_need_to_block not in self.blocked_ports:
                            self.logger.info(f"Port {self.port_need_to_block} is blocked!")
                            self.block_port(datapath, self.port_need_to_block)
                        return

                flow_serial_no = get_flow_number()
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, flow_serial_no, msg.buffer_id, idle=20, hard=100)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, flow_serial_no, idle=20, hard=100)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
