import switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import os
import numpy as np
from datetime import datetime

class NetworkTrainingStatisticsCollector(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(NetworkTrainingStatisticsCollector, self).__init__(*args, **kwargs)
        self.datapaths = {}  # Dictionary to store datapaths
        self.monitor_thread = hub.spawn(self.monitor)  # Spawn a thread to monitor the network
        self.label = 0  # Initial label for normal traffic
        self.flow_data = {}  # Dictionary to store flow data
        
        # Initialize the CSV file for storing traffic data
        self.init_csv()

    def init_csv(self):
        csv_file = "DDos_and_Normal_Traffic_Dataset.csv"
        # Extract 28 features
        headers = [
            'timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst', 'tp_dst', 'ip_proto', 
            'icmp_code', 'icmp_type', 'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout', 
            'hard_timeout', 'flags', 'packet_count', 'byte_count', 'packet_count_per_second', 
            'packet_count_per_nsecond', 'byte_count_per_second', 'byte_count_per_nsecond', 
            'avg_packet_size', 'flow_duration_total', 'idle_mean', 'idle_std', 'idle_max', 'idle_min', 'label'
        ]

        if not os.path.exists(csv_file):
            with open(csv_file, "w") as file:
                file.write(",".join(headers) + "\n")  # Write headers if file doesn't exist
        else:
            self.label = 1  # Set label to 1 for DDoS traffic if file already exists
            print("Generating data...")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath  # Register the datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]  # Unregister the datapath

    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)  # Request stats from each datapath
            hub.sleep(10)  # Sleep for 10 seconds before the next request

    def request_stats(self, datapath):
        self.logger.debug('Send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)  # Send stats request to the datapath

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()  # Get current timestamp
        body = ev.msg.body

        with open("DDos_and_Normal_Traffic_Dataset.csv", "a+") as file:
            for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow:
                (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

                flow_info = self.extract_flow_info(ev, stat, timestamp)  # Extract flow information
                file.write(",".join(map(str, flow_info)) + "\n")  # Write flow information to the CSV file

    def extract_flow_info(self, ev, stat, timestamp):
        ip_src = stat.match.get('ipv4_src', '0.0.0.0')  # Get source IP
        ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')  # Get destination IP
        ip_proto = stat.match.get('ip_proto', 0)  # Get IP protocol
        icmp_code = stat.match.get('icmpv4_code', -1)  # Get ICMP code
        icmp_type = stat.match.get('icmpv4_type', -1)  # Get ICMP type
        tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))  # Get TCP/UDP source port
        tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))  # Get TCP/UDP destination port

        flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"  # Generate flow ID

        if flow_id not in self.flow_data:
            self.flow_data[flow_id] = {'last_seen': timestamp, 'idle_times': []}  # Initialize flow data if not present
        else:
            idle_time = timestamp - self.flow_data[flow_id]['last_seen']  # Calculate idle time
            self.flow_data[flow_id]['idle_times'].append(idle_time)  # Append idle time to the list
            self.flow_data[flow_id]['last_seen'] = timestamp  # Update last seen timestamp

        packet_count_per_second = self.safe_divide(stat.packet_count, stat.duration_sec)  # Calculate packet count per second
        packet_count_per_nsecond = self.safe_divide(stat.packet_count, stat.duration_nsec)  # Calculate packet count per nanosecond
        byte_count_per_second = self.safe_divide(stat.byte_count, stat.duration_sec)  # Calculate byte count per second
        byte_count_per_nsecond = self.safe_divide(stat.byte_count, stat.duration_nsec)  # Calculate byte count per nanosecond
        avg_packet_size = self.safe_divide(stat.byte_count, stat.packet_count)  # Calculate average packet size

        flow_duration_total = stat.duration_sec + (stat.duration_nsec / 1e9)  # Calculate total flow duration

        idle_times = self.flow_data[flow_id]['idle_times']
        idle_mean = np.mean(idle_times) if idle_times else 0  # Calculate mean idle time
        idle_std = np.std(idle_times) if idle_times else 0  # Calculate standard deviation of idle time
        idle_max = np.max(idle_times) if idle_times else 0  # Calculate max idle time
        idle_min = np.min(idle_times) if idle_times else 0  # Calculate min idle time

        return [
            timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst, ip_proto, 
            icmp_code, icmp_type, stat.duration_sec, stat.duration_nsec, stat.idle_timeout, 
            stat.hard_timeout, stat.flags, stat.packet_count, stat.byte_count, 
            packet_count_per_second, packet_count_per_nsecond, byte_count_per_second, 
            byte_count_per_nsecond, avg_packet_size, flow_duration_total, idle_mean, 
            idle_std, idle_max, idle_min, self.label  # Return extracted flow information
        ]

    @staticmethod
    def safe_divide(numerator, denominator):
        return numerator / denominator if denominator else 0  # Safely divide to avoid division by zero
