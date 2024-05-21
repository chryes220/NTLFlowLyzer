from datetime import datetime, timezone
import json
import sys
import threading
import time
import os
import numpy as np
import pkg_resources
from multiprocessing import Pool
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from .network_flow_capturer.packet import Packet  # Ensure correct import based on project structure
from .network_flow_capturer.flow import Flow  # Ensure correct import based on project structure
from .feature_extractor import FeatureExtractor  # Add appropriate import based on your project
from .config_loader import ConfigLoader
from .model import Model 


class LiveNetworkSniffer:
    def __init__(self, iface: str, config: ConfigLoader, timeout=30, model='xgb-no-bot'):
        self.iface = iface
        self.ongoing_flows = {}
        self.timeout = timeout
        self.num_threads = 4
        self.stop_sniffing = threading.Event()

        self.packet_queue = Queue()
        self.feature_extraction_queue = Queue()
        self.ml_predictor_queue = Queue()
        self.log_writer_queue = Queue()

        self.packet_queue_lock = threading.Lock()
        self.feature_extraction_queue_lock = threading.Lock()
        self.ml_predictor_queue_lock = threading.Lock()
        self.log_writer_queue_lock = threading.Lock()
        self.ongoing_flows_lock = threading.Lock()

        self.sniffer_thread = threading.Thread(target=self.start_sniffing, name="Sniffer Thread")
        # self.packet_handler_thread = threading.Thread(target=self.packet_handler, name="Packet Handler Thread")
        # self.feature_extraction_thread = threading.Thread(target=self.feature_extraction_worker, name="Feature Extraction Thread")
        # self.ml_predictor_thread = threading.Thread(target=self.ml_predictor_worker, name="ML Predictor Thread")
        self.log_writer_thread = threading.Thread(target=self.log_writer_worker, name="CSV Writer Thread")
        
        self.packet_handler_thread = [threading.Thread(target=self.packet_handler) for _ in range(3)]
        self.feature_extraction_thread = [threading.Thread(target=self.feature_extraction_worker) for _ in range(3)]
        self.ml_predictor_thread = [threading.Thread(target=self.ml_predictor_worker) for _ in range(3)]
        # self.log_writer_thread = [threading.Thread(target=self.log_writer_worker) for _ in range(3)]

        self.config = config
        self.feature_extractor = FeatureExtractor(self.config.floating_point_unit)

        # load model
        try:
            models_dir = pkg_resources.resource_filename('NTLFlowLyzer', 'models')
            model_path = ''
            if model == 'xgb-no-bot':
                model_path = os.path.join(models_dir, 'xgb_no_bot.joblib')
            elif model == 'xgb-no-dos-hulk':
                model_path = os.path.join(models_dir, 'xgb_no_dos_hulk.joblib')
            elif model == 'xgb-no-dos-slowloris':
                model_path = os.path.join(models_dir, 'xgb_no_dos_slowloris.joblib')
            elif model == 'xgb-no-heartbleed':
                model_path = os.path.join(models_dir, 'xgb_no_heartbleed.joblib')
            else:
                # default is xgb no bot
                model_path = os.path.join(models_dir, 'xgb_no_bot.joblib')
        except Exception as e:
            print(f"Error loading model: {e}")
            sys.exit(1)

        self.model = Model(model, model_path)
        self.feature_keys = ['duration', 'fwd_packets_count', 'fwd_total_payload_bytes', 'fwd_payload_bytes_max',
                             'fwd_payload_bytes_min', 'bwd_payload_bytes_max', 'bwd_payload_bytes_min',
                             'bytes_rate', 'packets_rate', 'packets_IAT_mean', 'packets_IAT_std', 'packets_IAT_min', 
                             'bwd_packets_IAT_std', 'fwd_psh_flag_counts', 'fwd_urg_flag_counts', 'fwd_total_header_bytes', 
                             'bwd_total_header_bytes', 'bwd_packets_rate', 'payload_bytes_min', 'fin_flag_counts', 
                             'rst_flag_counts', 'psh_flag_counts', 'ack_flag_counts', 'urg_flag_counts',
                             'down_up_rate', 'fwd_init_win_bytes', 'bwd_init_win_bytes', 'fwd_segment_size_min',
                             'active_mean', 'active_std', 'idle_std']

        self.log_filename = r'/var/log/ntlflyzer.json'

        # self.worker_threads = [threading.Thread(target=self.packet_handler) for _ in range(num_worker_threads)]
        # self.sniffer_threads = [threading.Thread(target=self.start_sniffing) for _ in range(10)]
        
        # Initialize and start threads
        self.sniffer_thread.start()
        # self.packet_handler_thread.start()
        # self.feature_extraction_thread.start()
        # self.ml_predictor_thread.start()
        self.log_writer_thread.start()

        for packet_handler_thread in self.packet_handler_thread:
            packet_handler_thread.start()
        for feature_extraction_thread in self.feature_extraction_thread:
            feature_extraction_thread.start()
        for ml_predictor_thread in self.ml_predictor_thread:
            ml_predictor_thread.start()
        # for log_writer_thread in self.log_writer_thread:
        #     log_writer_thread.start()

        # for sniffer_thread in self.sniffer_threads:
        #     sniffer_thread.start()

    def get_packet(self, packet):
        self.packet_queue.put(packet)
        print(f"Packet: {packet}")

    def packet_handler(self):
        while not self.stop_sniffing.is_set():
            # if not self.packet_queue_lock.acquire(blocking=False):
            #     continue
            # print("A")
            if not self.packet_queue.empty():
                # with self.packet_queue_lock:
                # print("B")
                packet = self.packet_queue.get()
                
                try:
                    # Convert packet to bytes
                    new_buf = bytes(packet)
                    # print(f"Packet: {packet}")
                    # Decapsulate VXLAN packets
                    eth = Ether(new_buf)
                    # print(f"Packet: {eth}")
                    decapsulation = True
                    while decapsulation:
                        if not isinstance(eth.payload, IP):
                            decapsulation = False
                            break
                        ip = eth.payload
                        if (ip.src == self.config.vxlan_ip) or (ip.dst == self.config.vxlan_ip):
                            if not ((ip.src == self.config.vxlan_ip and ip.dst.startswith("10.0.")) or (ip.dst == self.config.vxlan_ip and ip.src.startswith("10.0."))):
                                decapsulation = False
                                break
                            # Decapsulate the inner packet
                            new_buf = bytes(eth.payload.payload.payload)
                            print(f"Decapsulated packet: {new_buf}")
                            eth = Ether(new_buf)
                        else:
                            decapsulation = False
                            break

                    if not isinstance(eth.payload, IP):
                        # print(f"!! Not an IP packet: {eth.payload}\n")
                        continue
                    ip = eth.payload

                    # print(f"Payload: {ip}")

                    # Extract TCP layer information
                    network_protocol = 'UNKNOWN'
                    if isinstance(ip.payload, TCP):
                        transport_layer = ip.payload
                        network_protocol = 'TCP'
                    elif isinstance(ip.payload, UDP):
                        transport_layer = ip.payload
                        network_protocol = 'UDP'
                    elif isinstance(ip.payload, ICMP):
                        transport_layer = ip.payload
                        network_protocol = 'ICMP'
                    else:
                        continue
                    
                    window_size = getattr(transport_layer, 'window', 0)
                    tcp_flags = getattr(transport_layer, 'flags', 0)
                    seq_number = getattr(transport_layer, 'seq', 0)
                    ack_number = getattr(transport_layer, 'ack', 0)

                    # Create a NTLFlowLyzer packet object
                    nlflyzer_packet = Packet(
                        src_ip=ip.src, 
                        src_port=getattr(transport_layer, 'sport', 0),
                        dst_ip=ip.dst, 
                        dst_port=getattr(transport_layer, 'dport', 0),
                        protocol=network_protocol, 
                        flags=tcp_flags,
                        timestamp=packet.time, 
                        length=len(new_buf),
                        payloadbytes=len(transport_layer.payload), 
                        header_size=len(ip.payload) - len(transport_layer.payload),
                        window_size=window_size,
                        seq_number=seq_number,
                        ack_number=ack_number)

                    # Add the packet to the ongoing flow
                    self.add_packet_to_flow(nlflyzer_packet)

                except Exception as e:
                    print(f"!! Exception happened!")
                    print(e)
                    print(30*"*")
                    continue
       
    def add_packet_to_flow(self, packet: Packet):
        flow_id = packet.get_flow_id()
        current_time = time.time()
        
        to_remove = []
        
        with self.ongoing_flows_lock:
            if flow_id in self.ongoing_flows:
                # print(f"Flow {flow_id} already exists")
                flow = self.ongoing_flows[flow_id]
                flow.add_packet(packet)
                flow.flow_last_seen = current_time
                if self.is_finished_flow(flow, packet):
                    # print(f"Flow {flow_id} is finished")
                    to_remove.append(flow_id)
            else:
                flow = Flow(packet, self.timeout)
                self.ongoing_flows[flow_id] = flow
                # print(f"New flow started: {flow_id}")
            # print("To remove: ", len(to_remove))
            # with self.feature_extraction_queue_lock:
            for flow_id in to_remove:
                self.feature_extraction_queue.put(self.ongoing_flows[flow_id])
                del self.ongoing_flows[flow_id]
                # print(f"Flow finished: {flow_id}")

    def is_finished_flow(self, flow: Flow, packet: Packet):
        flow_duration = datetime.fromtimestamp(float(packet.get_timestamp())) - datetime.fromtimestamp(float(flow.get_flow_start_time()))
        active_time = datetime.fromtimestamp(float(packet.get_timestamp())) - datetime.fromtimestamp(float(flow.get_flow_last_seen()))
        if flow_duration.total_seconds() > self.config.max_flow_duration \
                or active_time.total_seconds() > self.config.activity_timeout \
                or flow.has_two_FIN_flags() \
                or flow.has_flagRST():
            return True
        return False

    def start_sniffing(self):
        print(">> Sniffer started...")
        sniff(iface=self.iface, prn=self.packet_queue.put, stop_filter=lambda p: self.stop_sniffing.is_set())
        # sniffer = pcap.pcap(name=self.iface, promisc=True, immediate=True, timeout_ms=1000)
        # for ts, pkt in sniffer:
        #     if self.stop_sniffing.is_set():
        #         break
        #     with self.packet_queue_lock:
        #         self.packet_queue.put(pkt)
        print(">> Sniffer stopped...")

    def feature_extraction_worker(self):
        # checks if the feature extraction queue is empty
        while not self.stop_sniffing.is_set():
            if not self.feature_extraction_queue.empty():
                # if not self.feature_extraction_queue_lock.acquire(blocking=False):
                #     continue
                # print(f"Number of flows in feature extraction queue: {self.feature_extraction_queue.qsize()}")
                # with self.feature_extraction_queue_lock:
                flow = self.feature_extraction_queue.get()
                extracted_flow = self.feature_extractor.execute_single_flow(flow)
                
                # with self.ml_predictor_queue_lock:
                self.ml_predictor_queue.put(extracted_flow)
                # print(f"Flow {str(flow)} feature extraction completed.\n")

    def ml_predictor_worker(self):
        # checks if the ml prediction queue is empty
        while not self.stop_sniffing.is_set():
            if not self.ml_predictor_queue.empty():
                # if not self.ml_predictor_queue_lock.acquire(blocking=False):
                #     continue
                # with self.ml_predictor_queue_lock:
                flow_dict = self.ml_predictor_queue.get()
                # print(f"Flow {flow_dict['flow_id']} prediction started...")
                # print(f"Flow {flow_dict['flow_id']} features: {flow_dict}\n")
                x = np.array([flow_dict[key] for key in self.feature_keys], dtype=float)
                x = x.reshape(1, -1)
                # print(f"Flow {flow_dict['flow_id']} features: {x}\n")
                start = time.time()
                try:
                    prediction = self.model.predict(x)
                except Exception as e:
                    print(f"Error predicting flow {flow_dict['flow_id']}: {e}")
                    continue
                prediction_duration = time.time() - start

                result = {}
                result['flow_id'] = flow_dict['flow_id']
                result['timestamp'] = flow_dict['timestamp']
                result['src_ip'] = flow_dict['src_ip']
                result['src_port'] = flow_dict['src_port']
                result['dst_ip'] = flow_dict['dst_ip']
                result['src_port'] = flow_dict['src_port']
                result['protocol'] = flow_dict['protocol']
                result['label'] = int(prediction[0])
                result['prediction_duration'] = prediction_duration

                # print(f"Flow {flow_dict['flow_id']} prediction completed with prediction: {prediction[0]}.\n")

                # with self.log_writer_queue_lock:
                self.log_writer_queue.put(result)

    def log_writer_worker(self):
        with open(self.log_filename, 'a') as f:
            while not self.stop_sniffing.is_set():
                if not self.log_writer_queue.empty():
                    # if not self.log_writer_queue_lock.acquire(blocking=False):
                    #     continue
                    # with self.log_writer_queue_lock:
                        # write to self.log_filename
                    prediction = self.log_writer_queue.get()
                    # convert timestamp from datetime to string
                    try:
                        prediction['timestamp'] = prediction['timestamp'].astimezone(timezone.utc).isoformat()
                        json.dump(prediction, f)
                        f.write('\n')
                    except Exception as e:
                        print(f"Error writing flow {prediction['flow_id']} to log: {e}")
                        continue
                    # print(f"Flow {prediction['flow_id']} logged.\n")

    def run(self):
        try:
            while not self.stop_sniffing.is_set():
                time.sleep(10)
                print(f"Number of captured packets: {self.packet_queue.qsize()}")
                print(f"Number of ongoing flows: {len(self.ongoing_flows)}")
                print(f"Number of flows in feature extraction queue: {self.feature_extraction_queue.qsize()}")
                print(f"Number of flows in ML predictor queue: {self.ml_predictor_queue.qsize()}")
                print(f"Number of flows in log writer queue: {self.log_writer_queue.qsize()}\n")
        except KeyboardInterrupt:
            print("Keyboard interrupt received, stopping sniffer...")
            self.stop_sniffing.set()
        finally:
            # write all remaining items in log writer queue
            print("Writing remaining items in log writer queue...")
            with open(self.log_filename, 'a') as f:
                while not self.log_writer_queue.empty():
                    # with self.log_writer_queue_lock:
                    # write to self.log_filename
                    prediction = self.log_writer_queue.get()
                    # convert timestamp from datetime to string
                    prediction['timestamp'] = prediction['timestamp'].astimezone(timezone.utc).isoformat()
                    json.dump(prediction, f)
                    f.write('\n')

            # stop all threads
            self.sniffer_thread.join()
            # self.packet_handler_thread.join()
            # self.feature_extraction_thread.join()
            # self.ml_predictor_thread.join()
            self.log_writer_thread.join()

            for packet_handler_thread in self.packet_handler_thread:
                packet_handler_thread.join()
            for feature_extraction_thread in self.feature_extraction_thread:
                feature_extraction_thread.join()
            for ml_predictor_thread in self.ml_predictor_thread:
                ml_predictor_thread.join()
            # for log_writer_thread in self.log_writer_thread:
            #     log_writer_thread.join()

            # for sniffer_thread in self.sniffer_threads:
            #     sniffer_thread.join()

            print("Sniffer thread joined, cleanup complete.")

# Usage example
if __name__ == "__main__":
    iface = "Wi-Fi"  # Change this to your network interface
    sniffer = LiveNetworkSniffer(iface, 60)
    sniffer.run()
