from datetime import timezone
import hashlib
import json
import logging
import sys
import time
import os
import pkg_resources
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from threading import Event, Thread

from NTLFlowLyzer.network_flow_capturer.network_flow_handler import NetworkFlowHandler
from NTLFlowLyzer.network_flow_capturer.packet import Packet
from NTLFlowLyzer.model import Model
from NTLFlowLyzer.config_loader import ConfigLoader 


class LiveNetworkSniffer:
    def __init__(self, iface: str, config: ConfigLoader, model='xgb-no-bot'):
        self.iface = iface
        self.config = config
        self.num_threads = 4
        self.log_filename = r'/var/log/ntlflyzer.json'

        self.stop_sniffing = Event()

        self.existing_flows = {} # key: hash value of flow id, value: thread id
        self.packet_queue = Queue()

        self.sniffer_thread = Thread(target=self.start_sniffing, name="Sniffer Thread")
        self.packet_handler_thread = Thread(target=self.packet_handling_worker, name="Packet Handler Thread")
        self.finished_flow_thread = Thread(target=self.finished_flow_handler, name="Finished Flow Thread")
        self.log_collector_thread = Thread(target=self.log_collector_worker, name="Log Collector Thread")
  
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
            elif model == 'oc-svm':
                model_path = os.path.join(models_dir, 'ocsvm.joblib')
            else:
                # default is xgb no bot
                model_path = os.path.join(models_dir, 'xgb_no_bot.joblib')
        except Exception as e:
            print(f"Error loading model: {e}")
            sys.exit(1)

        self.model = Model(model, model_path)

        self.flow_handler_queues = [Queue() for _ in range(self.num_threads)]
        self.flow_handler_finished = [Queue() for _ in range(self.num_threads)] # contains flow ids
        self.flow_handler_logs = [Queue() for _ in range(self.num_threads)]
        self.flow_handler_flags = [Event() for _ in range(self.num_threads)]
        self.flow_handler_objects = [NetworkFlowHandler(self.config, self.model) for _ in range(self.num_threads)]
        self.flow_handler_threads = [Thread(target=flow_handler.run, args=(self.flow_handler_queues[i], self.flow_handler_logs[i], self.flow_handler_finished[i], self.stop_sniffing, self.flow_handler_flags[i]), name=f"Flow Handler Thread {i}") for i, flow_handler in enumerate(self.flow_handler_objects)]

        self.logger = logging.getLogger('log_writer')
        self.logger.setLevel(logging.INFO)
        self.file_handler = logging.FileHandler(self.log_filename)
        self.file_handler.setLevel(logging.INFO)
        self.logger.addHandler(self.file_handler)
        
        self.start()

    def start(self):
        self.sniffer_thread.start()
        self.packet_handler_thread.start()
        self.finished_flow_thread.start()
        self.log_collector_thread.start()
        for p in self.flow_handler_threads:
            # print(f"Starting flow handler {p.name}...")
            p.start()
        # print()
        print(f"Predicting with model: {self.model.name}\n")


    def stop(self):
        self.stop_sniffing.set()
        self.sniffer_thread.join()
        self.packet_handler_thread.join()
        self.finished_flow_thread.join()
        self.log_collector_thread.join()
        for p in self.flow_handler_threads:
            p.join()

    def hash_packet(self, flow_id: str):
        return hashlib.sha256(flow_id.encode()).hexdigest()

    def get_packet(self, packet):
        self.packet_queue.put(packet)
        print(f"Packet: {packet}")

    def create_new_packet(self, packet, ip, transport_layer, network_protocol, tcp_flags, new_buf, window_size, seq_number, ack_number):
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
        flow_id, alt_flow_id = nlflyzer_packet.get_flow_id()
        hashed_flow_id = self.hash_packet(flow_id)
        hashed_alt_flow_id = self.hash_packet(alt_flow_id)
        if hashed_flow_id in self.existing_flows:
            flow_idx = self.existing_flows[hashed_flow_id]
        elif hashed_alt_flow_id in self.existing_flows:
            flow_idx = self.existing_flows[hashed_alt_flow_id]
        else:
            flow_id_hash = self.hash_packet(flow_id)
            flow_idx = int(flow_id_hash, 16) % self.num_threads
            self.existing_flows[flow_id_hash] = flow_idx
        # add packet to flow handler queue
        self.flow_handler_queues[flow_idx].put(nlflyzer_packet)
        # print(f"Packet {flow_id} sent to flow handler {flow_idx}.\n")

    def handle_packet(self, packet):
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
                return
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
                # print(f"We get an ICMP Packet!!!")
                transport_layer = ip.payload
                network_protocol = 'ICMP'
            else:
                return
            
            window_size = getattr(transport_layer, 'window', 0)
            tcp_flags = getattr(transport_layer, 'flags', 0)
            seq_number = getattr(transport_layer, 'seq', 0)
            ack_number = getattr(transport_layer, 'ack', 0)

            # Create a new packet object
            self.create_new_packet(packet, ip, transport_layer, network_protocol, tcp_flags, new_buf, window_size, seq_number, ack_number)

        except Exception as e:
            print(f"!! Exception happened!")
            print(e)
            print(30*"*")
            return

    def packet_handling_worker(self):
        while not self.stop_sniffing.is_set():
            if not self.packet_queue.empty():
                packet = self.packet_queue.get()
                self.handle_packet(packet)

    def start_sniffing(self):
        print(">> Sniffer started...")
        sniff(iface=self.iface, prn=self.packet_queue.put, stop_filter=lambda p: self.stop_sniffing.is_set())
        print(">> Sniffer stopped...")

    def finished_flow_handler(self):
        while not self.stop_sniffing.is_set():
            for i, q in enumerate(self.flow_handler_finished):
                if not q.empty():
                    finished_flow = q.get()
                    hashed_flow_id = self.hash_packet(finished_flow)
                    try:
                        del self.existing_flows[hashed_flow_id]
                    except KeyError:
                        continue
                        # print(f"Flow {finished_flow} not found in existing flows.")

    def log_collector_worker(self):
        while not self.stop_sniffing.is_set():
            for i, q in enumerate(self.flow_handler_logs):
                if not q.empty():
                    log = q.get()
                    self.write_log(log)

    def write_log(self, prediction):
        try:
            # convert timestamp from datetime to string
            prediction['timestamp'] = prediction['timestamp'].astimezone(timezone.utc).isoformat()
            self.logger.info(json.dumps(prediction))
            print(f"Flow {prediction['flow_id']} logged.\n")
        except Exception as e:
            print(f"Error writing flow {prediction['flow_id']} to log: {e}")

    def log_writer_worker(self):
        while not self.stop_sniffing.is_set():
            if not self.log_writer_queue.empty():
                prediction = self.log_writer_queue.get()
                self.write_log(prediction)

    def finish_jobs(self):
        print("Finishing jobs...")
        print("Handling remaining packets in the queue...")
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            self.handle_packet(packet)

        # wait until all threads finished their jobs and set finished signal
        for flag in self.flow_handler_flags:
            flag.wait()

        # write all remaining items in log writer queue
        print("Writing remaining items in log writer queue...")
        for i, q in enumerate(self.flow_handler_logs):
            while not q.empty():
                prediction = q.get()
                self.write_log(prediction)

    def run(self):
        try:
            while not self.stop_sniffing.is_set():
                time.sleep(10)
                print(f"Number of captured packets: {self.packet_queue.qsize()}")
                for i, q in enumerate(self.flow_handler_queues):
                    print(f"Number of packets in flow handler {i} queue: {q.qsize()}")
                print()
        except KeyboardInterrupt:
            print("Keyboard interrupt received, stopping sniffer...")
            self.stop_sniffing.set()
        finally:
            self.finish_jobs()

            # stop all threads
            self.stop()
            print("Sniffer thread joined, cleanup complete.")

# Usage example
if __name__ == "__main__":
    iface = "Wi-Fi"  # Change this to your network interface
    sniffer = LiveNetworkSniffer(iface, 60)
    sniffer.run()
