from datetime import datetime, timezone
import hashlib
import json
import multiprocessing
import sys
import threading
import time
import os
import numpy as np
import pkg_resources
from multiprocessing import Pool, Process
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from threading import Event, Thread

from NTLFlowLyzer.network_flow_capturer.network_flow_handler import NetworkFlowHandler
from .network_flow_capturer.packet import Packet  # Ensure correct import based on project structure
from .network_flow_capturer.flow import Flow  # Ensure correct import based on project structure
from .feature_extractor import FeatureExtractor  # Add appropriate import based on your project
from .config_loader import ConfigLoader
from .model import Model 


class LiveNetworkSniffer:
    def __init__(self, iface: str, config: ConfigLoader, timeout=30, model='xgb-no-bot'):
        self.iface = iface
        self.config = config
        self.timeout = timeout
        self.num_threads = 4
        self.log_filename = r'/var/log/ntlflyzer.json'

        self.stop_sniffing = Event()

        self.packet_queue = Queue()
        self.log_writer_queue = Queue()

        self.sniffer_thread = Thread(target=self.start_sniffing, name="Sniffer Thread")
        self.packet_handler_thread = Thread(target=self.packet_handler, name="Packet Handler Thread")
        self.log_collector_thread = Thread(target=self.log_collector, name="Log Collector Thread")
        self.log_writer_thread = Thread(target=self.log_writer_worker, name="CSV Writer Thread")
  
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

        self.flow_handler_queues = [Queue() for _ in range(self.num_threads)]
        self.flow_handler_logs = [Queue() for _ in range(self.num_threads)]
        self.flow_handler_objects = [NetworkFlowHandler(self.config, self.timeout, self.model) for _ in range(self.num_threads)]
        self.flow_handler_threads = [Thread(target=flow_handler.run, args=(self.flow_handler_queues[i], self.log_writer_queue, self.stop_sniffing), name=f"Flow Handler Thread {i}") for i, flow_handler in enumerate(self.flow_handler_objects)]

        self.start()

    def start(self):
        self.sniffer_thread.start()
        self.packet_handler_thread.start()
        self.log_collector_thread.start()
        self.log_writer_thread.start()
        for p in self.flow_handler_threads:
            print(f"Starting flow handler {p.name}...")
            p.start()

    def stop(self):
        self.stop_sniffing.set()
        self.sniffer_thread.join()
        self.packet_handler_thread.join()
        self.log_collector_thread.join()
        self.log_writer_thread.join()
        for p in self.flow_handler_threads:
            p.join()

    def hash_packet(self, flow_id: str):
        return hashlib.sha256(flow_id.encode()).hexdigest()

    def get_packet(self, packet):
        self.packet_queue.put(packet)
        print(f"Packet: {packet}")

    def packet_handler(self):
        while not self.stop_sniffing.is_set():
            if not self.packet_queue.empty():
                packet = self.packet_queue.get()
                # print(f"Packet: {packet}")
                
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

                    # hash the packet
                    flow_id = nlflyzer_packet.get_flow_id()
                    flow_id_hash = self.hash_packet(flow_id)
                    flow_idx = int(flow_id_hash, 16) % self.num_threads
                    self.flow_handler_queues[flow_idx].put(nlflyzer_packet)
                    # print(f"Packet {flow_id} sent to flow handler {flow_idx}.\n")

                except Exception as e:
                    print(f"!! Exception happened!")
                    print(e)
                    print(30*"*")
                    continue
       
    def start_sniffing(self):
        print(">> Sniffer started...")
        sniff(iface=self.iface, prn=self.packet_queue.put, stop_filter=lambda p: self.stop_sniffing.is_set())
        print(">> Sniffer stopped...")

    def log_collector(self):
        while not self.stop_sniffing.is_set():
            for i, q in enumerate(self.flow_handler_logs):
                if not q.empty():
                    log = q.get()
                    self.log_writer_queue.put(log)
                    # print(f"Flow {log['flow_id']} logged.\n")

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
                for i, q in enumerate(self.flow_handler_queues):
                    print(f"Number of flows in flow handler {i} queue: {q.qsize()}")
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
            self.packet_handler_thread.join()
            self.log_collector_thread.join()
            self.log_writer_thread.join()
            for p in self.flow_handler_threads:
                p.join()

            print("Sniffer thread joined, cleanup complete.")

# Usage example
if __name__ == "__main__":
    iface = "Wi-Fi"  # Change this to your network interface
    sniffer = LiveNetworkSniffer(iface, 60)
    sniffer.run()
