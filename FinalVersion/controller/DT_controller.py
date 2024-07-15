from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub

import switch
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import confusion_matrix, accuracy_score

class SimpleMonitor13(switch.SimpleSwitch13):
    
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.flow_data = {}

        print("Start training...")
        start = datetime.now()
        self.flow_training()
        end = datetime.now()
        print("End training!")
        print("Training time: ", (end - start))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(20) # Increase Request Interval to 20 Seconds
            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()

        file = open("PredictTrafficStatsFile.csv","w")
        file.write(
            'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
            'flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,'
            'packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond,'
            'avg_packet_size,flow_duration_total,idle_mean,idle_std,idle_max,idle_min\n'
        )

        body = ev.msg.body
        for stat in sorted([flow for flow in body if flow.priority == 1],
            key=lambda flow: (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']
            tp_src, tp_dst, icmp_code, icmp_type = 0, 0, -1, -1

            if ip_proto == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']
            elif ip_proto == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']
            elif ip_proto == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"
            self._update_flow_data(flow_id, timestamp)

            packet_count_per_second = self.safe_divide(stat.packet_count, stat.duration_sec)
            packet_count_per_nsecond = self.safe_divide(stat.packet_count, stat.duration_nsec)
            byte_count_per_second = self.safe_divide(stat.byte_count, stat.duration_sec)
            byte_count_per_nsecond = self.safe_divide(stat.byte_count, stat.duration_nsec)
            avg_packet_size = self.safe_divide(stat.byte_count, stat.packet_count)
            flow_duration_total = stat.duration_sec + (stat.duration_nsec / 1e9)
            idle_mean, idle_std, idle_max, idle_min = self._calculate_idle_times(flow_id)

            file.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src,ip_dst, tp_dst,
                        stat.match['ip_proto'],icmp_code,icmp_type,
                        stat.duration_sec, stat.duration_nsec,
                        stat.idle_timeout, stat.hard_timeout,
                        stat.flags, stat.packet_count,stat.byte_count,
                        packet_count_per_second,packet_count_per_nsecond,
                        byte_count_per_second,byte_count_per_nsecond,
                        avg_packet_size, flow_duration_total, idle_mean, 
                        idle_std, idle_max, idle_min, avg_packet_size, 
                        flow_duration_total, idle_mean, idle_std, idle_max, idle_min))
        file.close()

    def _update_flow_data(self, flow_id, timestamp):
        if flow_id not in self.flow_data:
            self.flow_data[flow_id] = {'last_seen': timestamp, 'idle_times': []}
        else:
            idle_time = timestamp - self.flow_data[flow_id]['last_seen']
            self.flow_data[flow_id]['idle_times'].append(idle_time)
            self.flow_data[flow_id]['last_seen'] = timestamp

    def _calculate_idle_times(self, flow_id):
        idle_times = self.flow_data[flow_id]['idle_times']
        if idle_times:
            idle_mean = np.mean(idle_times)
            idle_std = np.std(idle_times)
            idle_max = np.max(idle_times)
            idle_min = np.min(idle_times)
        else:
            idle_mean = idle_std = idle_max = idle_min = 0
        return idle_mean, idle_std, idle_max, idle_min

    @staticmethod
    def safe_divide(numerator, denominator):
        return numerator / denominator if denominator else 0

    def flow_training(self):
        flow_dataset = pd.read_csv('DDos_and_Normal_Traffic_Dataset.csv')
        flow_dataset = self._preprocessing_dataset(flow_dataset)

        X_flow = flow_dataset.drop('label', axis=1).values.astype(float)
        y_flow = flow_dataset['label'].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.2, random_state=0)
        classifier = DecisionTreeClassifier(max_depth=10, min_samples_split=10, min_samples_leaf=5, criterion='entropy', random_state=0)
        self.flow_model = classifier.fit(X_flow_train, y_flow_train)

        y_flow_pred = self.flow_model.predict(X_flow_test)
        self._log_training_results(y_flow_test, y_flow_pred)

    def _preprocessing_dataset(self, dataset):
        # Delete unnecessary columns
        dataset = dataset.drop(['timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst', 'tp_dst', 'ip_proto', 'icmp_code', 'icmp_type'], axis=1)
        # Replace dots in IP addresses to convert to numerical representation
        dataset['ip_dst'] = dataset['ip_dst'].str.replace('.', '')
        return dataset

    def _log_training_results(self, y_true, y_pred):
        cm = confusion_matrix(y_true, y_pred)
        acc = accuracy_score(y_true, y_pred)

        self.logger.info("------------------------------------------------------------------------------")
        self.logger.info("Confusion matrix")
        self.logger.info(cm)
        self.logger.info("Success accuracy = {:.2f} %".format(acc * 100))
        self.logger.info("Fail accuracy = {:.2f} %".format((1.0 - acc) * 100))
        self.logger.info("------------------------------------------------------------------------------")

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictTrafficStatsFile.csv')
            predict_flow_dataset = self._preprocessing_dataset(predict_flow_dataset)

            X_predict_flow = predict_flow_dataset.values.astype('float64')
            y_flow_pred = self.flow_model.predict(X_predict_flow)

            self._log_prediction_results(y_flow_pred, predict_flow_dataset)
            self._reset_prediction_file()

        except:
            pass

    def _log_prediction_results(self, y_pred, dataset):
        legitimate_trafic = sum(1 for i in y_pred if i == 0)
        ddos_trafic = len(y_pred) - legitimate_trafic
        
        # Checks if the proportion of legitimate traffic is greater than 80%. If it is, it logs "Legitimate traffic". If not, it logs "DDos attack is detected!!!".
        if (legitimate_trafic / (legitimate_trafic + ddos_trafic) * 100) > 80:
            self.logger.info("Benign traffic ...")
        else:
            # If two last traffic have the same destination, then display the Victim host
            # Else traffic hasn't been completed yet, so I cannot correctly identify the Victim host
            if (int(dataset.loc[ddos_trafic - 2, 'ip_dst']) == int(dataset.loc[ddos_trafic - 1, 'ip_dst'])):
                print(dataset)
                self.logger.warning("DDos attack is detected!!!")
                victim = int(dataset.loc[ddos_trafic - 1, 'ip_dst']) % 10
                self.logger.warning(f"Victim is host: h{victim}")
        self.logger.info("------------------------------------------------------------------------------")
        self.logger.info("------------------------------------------------------------------------------")

    @staticmethod
    def _reset_prediction_file():
        file = open("PredictTrafficStatsFile.csv","w")
        file.write(
            'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
            'flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,'
            'packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond,'
            'avg_packet_size,flow_duration_total,idle_mean,idle_std,idle_max,idle_min\n'
        )
        file.close()
