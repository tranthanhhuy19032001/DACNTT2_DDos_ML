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
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)
        self.label = 0
        self.flow_data = {}
        
        # Initialize the CSV file
        self.init_csv()

    def init_csv(self):
        csv_file = "DDos_and_Normal_Traffic_Dataset.csv"
        headers = [
            'timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst', 'tp_dst', 'ip_proto', 
            'icmp_code', 'icmp_type', 'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout', 
            'hard_timeout', 'flags', 'packet_count', 'byte_count', 'packet_count_per_second', 
            'packet_count_per_nsecond', 'byte_count_per_second', 'byte_count_per_nsecond', 
            'avg_packet_size', 'flow_duration_total', 'idle_mean', 'idle_std', 'idle_max', 'idle_min', 'label'
        ]

        if not os.path.exists(csv_file):
            with open(csv_file, "w") as file:
                file.write(",".join(headers) + "\n")
        else:
            self.label = 1
            print("Generating data...")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(10)

    def request_stats(self, datapath):
        self.logger.debug('Send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        body = ev.msg.body

        with open("DDos_and_Normal_Traffic_Dataset.csv", "a+") as file:
            for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow:
                (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

                flow_info = self.extract_flow_info(ev, stat, timestamp)
                file.write(",".join(map(str, flow_info)) + "\n")

    def extract_flow_info(self, ev, stat, timestamp):
        ip_src = stat.match.get('ipv4_src', '0.0.0.0')
        ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
        ip_proto = stat.match.get('ip_proto', 0)
        icmp_code = stat.match.get('icmpv4_code', -1)
        icmp_type = stat.match.get('icmpv4_type', -1)
        tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
        tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))

        flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"

        if flow_id not in self.flow_data:
            self.flow_data[flow_id] = {'last_seen': timestamp, 'idle_times': []}
        else:
            idle_time = timestamp - self.flow_data[flow_id]['last_seen']
            self.flow_data[flow_id]['idle_times'].append(idle_time)
            self.flow_data[flow_id]['last_seen'] = timestamp

        packet_count_per_second = self.safe_divide(stat.packet_count, stat.duration_sec)
        packet_count_per_nsecond = self.safe_divide(stat.packet_count, stat.duration_nsec)
        byte_count_per_second = self.safe_divide(stat.byte_count, stat.duration_sec)
        byte_count_per_nsecond = self.safe_divide(stat.byte_count, stat.duration_nsec)
        avg_packet_size = self.safe_divide(stat.byte_count, stat.packet_count)

        flow_duration_total = stat.duration_sec + (stat.duration_nsec / 1e9)

        idle_times = self.flow_data[flow_id]['idle_times']
        idle_mean = np.mean(idle_times) if idle_times else 0
        idle_std = np.std(idle_times) if idle_times else 0
        idle_max = np.max(idle_times) if idle_times else 0
        idle_min = np.min(idle_times) if idle_times else 0

        return [
            timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst, ip_proto, 
            icmp_code, icmp_type, stat.duration_sec, stat.duration_nsec, stat.idle_timeout, 
            stat.hard_timeout, stat.flags, stat.packet_count, stat.byte_count, 
            packet_count_per_second, packet_count_per_nsecond, byte_count_per_second, 
            byte_count_per_nsecond, avg_packet_size, flow_duration_total, idle_mean, 
            idle_std, idle_max, idle_min, self.label
        ]

    @staticmethod
    def safe_divide(numerator, denominator):
        return numerator / denominator if denominator else 0
