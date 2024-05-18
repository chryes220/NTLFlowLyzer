from datetime import datetime
import threading
import time
from multiprocessing import Pool
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP, ICMP
from .network_flow_capturer.packet import Packet  # Ensure correct import based on project structure
from .network_flow_capturer.flow import Flow  # Ensure correct import based on project structure
from .feature_extractor import FeatureExtractor  # Add appropriate import based on your project
from .writers.writer import Writer, CSVWriter  # Add appropriate import based on your project
from .config_loader import ConfigLoader


class LiveNetworkSniffer:
    def __init__(self, iface: str, config: ConfigLoader, timeout=30):
        self.iface = iface
        self.ongoing_flows = {}
        self.timeout = timeout
        self.stop_sniffing = threading.Event()
        self.feature_extraction_queue = Queue()
        self.csv_writer_queue = Queue()
        self.sniffer_thread = threading.Thread(target=self.start_sniffing, name="Sniffer Thread")
        self.feature_extraction_thread = threading.Thread(target=self.feature_extraction_worker, name="Feature Extraction Thread")
        self.csv_writer_thread = threading.Thread(target=self.csv_writing_worker, name="CSV Writer Thread")
        self.lock = threading.Lock()
        self.config = config

        # Initialize and start threads
        self.sniffer_thread.start()
        self.feature_extraction_thread.start()
        self.csv_writer_thread.start()

    def packet_handler(self, packet):
        if not (IP in packet):
            return

        with self.lock:
            flow_id = self.get_flow_id(packet)
            current_time = time.time()
            
            pkt = Packet(
                src_ip=packet[IP].src,
                src_port=packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0),
                dst_ip=packet[IP].dst,
                dst_port=packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0),
                protocol=packet[IP].proto,
                flags=packet[TCP].flags if TCP in packet else 0,
                timestamp=current_time,
                forward=True,
                length=len(packet),
                payloadbytes=len(packet[TCP].payload) if TCP in packet else (len(packet[UDP].payload) if UDP in packet else 0),
                header_size=len(packet) - len(packet[TCP].payload) if TCP in packet else (len(packet) - len(packet[UDP].payload) if UDP in packet else 0),
                window_size=packet[TCP].window if TCP in packet else 0,
                seq_number=packet[TCP].seq if TCP in packet else 0,
                ack_number=packet[TCP].ack if TCP in packet else 0
            )

            to_remove = []
            
            if flow_id in self.ongoing_flows:
                flow = self.ongoing_flows[flow_id]
                flow.add_packet(pkt)
                flow.flow_last_seen = current_time
                if self.is_finished_flow(flow, pkt):
                    to_remove.append(flow_id)
            else:
                flow = Flow(pkt, self.timeout)
                self.ongoing_flows[flow_id] = flow
                # print(f"New flow started: {flow_id}")

            # Clean up old flows and add to feature extraction queue
            for flow_id in to_remove:
                self.feature_extraction_queue.put(self.ongoing_flows[flow_id])
                del self.ongoing_flows[flow_id]
                # print(f"Flow finished: {flow_id}")

    def get_flow_id(self, packet):
        if TCP in packet or UDP in packet:
            # get scapy sniff protocol
            proto = TCP if TCP in packet else UDP
            src = packet[IP].src
            dst = packet[IP].dst
            sport = packet[proto].sport
            dport = packet[proto].dport
            return f"{src}:{sport}-{dst}:{dport}-{proto.name}"
        else:
            return f"{packet[IP].src}-{packet[IP].dst}"

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
        sniff(iface=self.iface, prn=self.packet_handler, stop_filter=lambda p: self.stop_sniffing.is_set())
        print(">> Sniffer stopped...")

    def feature_extraction_worker(self):
        self.feature_extractor = FeatureExtractor(self.config.floating_point_unit)
        # checks if the feature extraction queue is empty
        while not self.stop_sniffing.is_set():
            if not self.feature_extraction_queue.empty():
                print(f"Number of flows in feature extraction queue: {self.feature_extraction_queue.qsize()}")
                with self.lock:
                    flows = self.feature_extraction_queue.get()
                    self.feature_extractor.execute_single_flow(flows)
                    # add to csv writing queue
                    self.csv_writer_queue.put(flows)
                


    def csv_writing_worker(self):
        self.writer = Writer(CSVWriter())
        header_writing_mode = 'w'
        data_writing_mode = 'a+'
        file_address = self.config.output_file_address
        write_headers = True

        # checks if the csv writing queue is empty
        # while not self.stop_sniffing.is_set() or not self.feature_extraction_queue.empty():
        #     if not self.feature_extraction_queue.empty():
        #         flows = self.feature_extraction_queue.get()
        #         self.writer.write(self.writer, flows)

    def run(self):
        try:
            while not self.stop_sniffing.is_set():
                time.sleep(10)
                # Flush finished flows to feature extraction queue
                # if self.finished_flows:
                #     self.feature_extraction_queue.put(self.finished_flows)
                #     self.finished_flows = []
                print(f"Number of ongoing flows: {len(self.ongoing_flows)}")
                print(f"Number of finished flows: {self.feature_extraction_queue.qsize()}")
                # Process finished flows here
        except KeyboardInterrupt:
            print("Keyboard interrupt received, stopping sniffer...")
            self.stop_sniffing.set()
        finally:
            # write all csv writing queue to csv
            if not self.csv_writer_queue.empty():
                flows = self.csv_writer_queue.get()
                self.writer.write(self.writer, flows)
            self.sniffer_thread.join()
            self.feature_extraction_thread.join()
            self.csv_writer_thread.join()
            print("Sniffer thread joined, cleanup complete.")

# Usage example
if __name__ == "__main__":
    iface = "Wi-Fi"  # Change this to your network interface
    sniffer = LiveNetworkSniffer(iface, 60)
    sniffer.run()
