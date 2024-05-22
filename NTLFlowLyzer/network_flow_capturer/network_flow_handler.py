from datetime import datetime
from queue import Queue
import numpy as np
from threading import Event
import time

from NTLFlowLyzer.config_loader import ConfigLoader
from NTLFlowLyzer.feature_extractor import FeatureExtractor
from NTLFlowLyzer.model import Model
from NTLFlowLyzer.network_flow_capturer.flow import Flow
from NTLFlowLyzer.network_flow_capturer.packet import Packet


class NetworkFlowHandler:
  def __init__(self, config: ConfigLoader, timeout: float, model: Model):
    self.config = config
    self.timeout = timeout
    self.stop_processsing = False

    self.feature_extractor = FeatureExtractor(self.config.floating_point_unit)

    # load model
    self.model = model
    self.feature_keys = ['duration', 'fwd_packets_count', 'fwd_total_payload_bytes', 'fwd_payload_bytes_max',
                         'fwd_payload_bytes_min', 'bwd_payload_bytes_max', 'bwd_payload_bytes_min',
                         'bytes_rate', 'packets_rate', 'packets_IAT_mean', 'packets_IAT_std', 'packets_IAT_min', 
                         'bwd_packets_IAT_std', 'fwd_psh_flag_counts', 'fwd_urg_flag_counts', 'fwd_total_header_bytes', 
                         'bwd_total_header_bytes', 'bwd_packets_rate', 'payload_bytes_min', 'fin_flag_counts', 
                         'rst_flag_counts', 'psh_flag_counts', 'ack_flag_counts', 'urg_flag_counts',
                         'down_up_rate', 'fwd_init_win_bytes', 'bwd_init_win_bytes', 'fwd_segment_size_min',
                         'active_mean', 'active_std', 'idle_std']

    self.ongoing_flows = {}

  def run(self, local_packet_queue: Queue, log_writer_queue: Queue, stop_processing: Event):
    while not stop_processing.is_set():
      if not local_packet_queue.empty():
        packet = local_packet_queue.get()
        to_remove = self.add_packet_to_flow(packet)
        for flow_id in to_remove:
          extracted_features = self.extract_feature(self.ongoing_flows[flow_id])
          x = np.array([extracted_features[key] for key in self.feature_keys], dtype=float)
          x = x.reshape(1, -1)
          # print(f"Flow {flow_dict['flow_id']} features: {x}\n")
          start = time.time()
          try:
              prediction = self.model.predict(x)
          except Exception as e:
              print(f"Error predicting flow {extracted_features['flow_id']}: {e}")
              continue
          prediction_duration = time.time() - start

          result = {}
          result['flow_id'] = extracted_features['flow_id']
          result['timestamp'] = extracted_features['timestamp']
          result['src_ip'] = extracted_features['src_ip']
          result['src_port'] = extracted_features['src_port']
          result['dst_ip'] = extracted_features['dst_ip']
          result['src_port'] = extracted_features['src_port']
          result['protocol'] = extracted_features['protocol']
          result['label'] = int(prediction[0])
          result['prediction_duration'] = prediction_duration

          # print(f"Flow {extracted_features['flow_id']} prediction completed with prediction: {prediction[0]}.\n")

          log_writer_queue.put(result)

  def add_packet_to_flow(self, packet: Packet):
    flow_id = packet.get_flow_id()
    current_time = time.time()
    
    to_remove = []
    
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

    return to_remove

  def is_finished_flow(self, flow: Flow, packet: Packet):
    flow_duration = datetime.fromtimestamp(float(packet.get_timestamp())) - datetime.fromtimestamp(float(flow.get_flow_start_time()))
    active_time = datetime.fromtimestamp(float(packet.get_timestamp())) - datetime.fromtimestamp(float(flow.get_flow_last_seen()))
    if flow_duration.total_seconds() > self.config.max_flow_duration \
      or active_time.total_seconds() > self.config.activity_timeout \
      or flow.has_two_FIN_flags() \
      or flow.has_flagRST():
      return True
    return False
  
  def extract_feature(self, flow: Flow):
    # print(f"Extracting features of flow {flow}")
    return self.feature_extractor.execute_single_flow(flow)
