from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub

import switch
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

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
        # Handle changes in the state of the switch (register/unregister)
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
        # Monitor the switches and request statistics at regular intervals
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(20)  # Request interval is 20 seconds
            self.flow_predict()

    def _request_stats(self, datapath):
        # Send a request to get flow statistics from the switch
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        # Handle the reply from the switch with flow statistics
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

            # Extract flow information from the statistics
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

            # Write flow statistics to the prediction file
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
        # Update the flow data with the latest timestamp and idle time
        if flow_id not in self.flow_data:
            self.flow_data[flow_id] = {'last_seen': timestamp, 'idle_times': []}
        else:
            idle_time = timestamp - self.flow_data[flow_id]['last_seen']
            self.flow_data[flow_id]['idle_times'].append(idle_time)
            self.flow_data[flow_id]['last_seen'] = timestamp

    def _calculate_idle_times(self, flow_id):
        # Calculate idle times statistics
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
        # Safely divide two numbers to avoid division by zero
        return numerator / denominator if denominator else 0

    def flow_training(self):
        # Train the KNN model using the dataset
        dataset = pd.read_csv('DDos_and_Normal_Traffic_Dataset.csv')
        flow_dataset = self._preprocessing_data_for_training(dataset)

        X_flow = flow_dataset.drop('label', axis=1).values.astype(float)
        y_flow = flow_dataset['label'].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)
        classifier = KNeighborsClassifier(n_neighbors=5, metric='minkowski', p=2)
        self.flow_model = classifier.fit(X_flow_train, y_flow_train)

        y_flow_pred = self.flow_model.predict(X_flow_test)
        self._log_training_results(y_flow_test, y_flow_pred)

    # Preprocess the dataset for training
    def _preprocessing_data_for_training(self, dataset):
        # Extract 15 features
        dataset = dataset[['ip_src', 'ip_dst', 'flow_duration_nsec', 'flags', 'packet_count', 'flow_duration_sec', 'byte_count', 'packet_count_per_second', 'byte_count_per_second', 'avg_packet_size', 'flow_duration_total', 'idle_mean', 'idle_std', 'idle_max', 'idle_min', 'label']]
        dataset.loc[:, 'ip_src'] = dataset['ip_src'].str.replace('.', '')
        dataset.loc[:, 'ip_dst'] = dataset['ip_dst'].str.replace('.', '')
        return dataset
        
    # Preprocess the dataset for prediction
    def _preprocessing_data_for_predict(self, dataset):
        # Extract 15 features
        dataset = dataset[['ip_src', 'ip_dst', 'flow_duration_nsec', 'flags', 'packet_count', 'flow_duration_sec', 'byte_count', 'packet_count_per_second', 'byte_count_per_second', 'avg_packet_size', 'flow_duration_total', 'idle_mean', 'idle_std', 'idle_max', 'idle_min']]
        dataset.loc[:, 'ip_src'] = dataset['ip_src'].str.replace('.', '')
        dataset.loc[:, 'ip_dst'] = dataset['ip_dst'].str.replace('.', '')
        return dataset

    def _log_training_results(self, y_true, y_pred):
        # Log the results of the training process
        cm = confusion_matrix(y_true, y_pred)
        acc = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, average='weighted')
        recall = recall_score(y_true, y_pred, average='weighted')
        f1 = f1_score(y_true, y_pred, average='weighted')

        self.logger.info("------------------------------------------------------------------------------")
        self.logger.info("Confusion matrix")
        self.logger.info(cm)
        self.logger.info("Success accuracy = {:.3f} %".format(acc * 100))
        self.logger.info("Fail accuracy = {:.3f} %".format((1 - acc) * 100))
        self.logger.info("Precision = {:.3f} %".format((1.0 - acc) * 100))
        self.logger.info("Recall = {:.3f} %".format(recall * 100))
        self.logger.info("F1 Score = {:.3f} %".format(f1 * 100))
        self.logger.info("------------------------------------------------------------------------------")

    def flow_predict(self):
        # Predict the traffic type using the trained model
        try:
            dataset = pd.read_csv('PredictTrafficStatsFile.csv')
            predict_flow_dataset = self._preprocessing_data_for_predict(dataset)

            X_predict_flow = predict_flow_dataset.values.astype(float)
            y_flow_pred = self.flow_model.predict(X_predict_flow)
            self._log_prediction_results(y_flow_pred, predict_flow_dataset)
            self._reset_prediction_file()

        except:
            pass

    def _log_prediction_results(self, y_pred, dataset):
        # Log the results of the prediction process
        print("---SHOW RESULT---")
        legitimate_trafic = sum(1 for i in y_pred if i == 0)
        ddos_trafic = len(y_pred) - legitimate_trafic
        
        # Checks if the proportion of legitimate traffic is greater than 80%. If it is, it logs "Legitimate traffic". If not, it logs "DDos attack is detected!!!".
        if (legitimate_trafic / (legitimate_trafic + ddos_trafic) * 100) > 80:
            self.logger.info("Benign traffic ...")
        else:
            # If two last traffic have the same destination, then display the Victim host
            # Else traffic hasn't been completed yet, so I cannot correctly identify the Victim host
            if (int(dataset.iloc[ddos_trafic - 2, 1]) == int(dataset.iloc[ddos_trafic - 1, 1])):
                #print(dataset)
                self.logger.warning("DDos attack is detected!!!")
                victim = int(dataset.iloc[ddos_trafic - 1, 1]) % 10
                if victim == 0:
                    victim += 1
                self.logger.warning(f"Victim is host: h{victim}")
        self.logger.info("------------------------------------------------------------------------------")
        self.logger.info("------------------------------------------------------------------------------")

    @staticmethod
    def _reset_prediction_file():
        # Reset the prediction file for the next batch of predictions
        file = open("PredictTrafficStatsFile.csv","w")
        file.write(
            'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
            'flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,'
            'packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond,'
            'avg_packet_size,flow_duration_total,idle_mean,idle_std,idle_max,idle_min\n'
        )
        file.close()
