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

  def predict_flow(self, flow: Flow):
    extracted_features = self.extract_feature(flow)
    
    x = np.array([extracted_features[key] for key in self.feature_keys], dtype=float)
    x = x.reshape(1, -1)
    # print(f"Flow {flow_dict['flow_id']} features: {x}\n")
    start = time.time()
    try:
        prediction = self.model.predict(x)
    except Exception as e:
        print(f"Error predicting flow {extracted_features['flow_id']}: {e}")
        return
    prediction_duration = time.time() - start

    result = {}
    result['flow_id'] = extracted_features['flow_id']
    result['timestamp'] = extracted_features['timestamp']
    result['src_ip'] = extracted_features['src_ip']
    result['src_port'] = extracted_features['src_port']
    result['dst_ip'] = extracted_features['dst_ip']
    result['dst_port'] = extracted_features['dst_port']
    result['protocol'] = extracted_features['protocol']
    result['label'] = int(prediction[0])
    result['prediction_duration'] = prediction_duration

    # print(f"Flow {extracted_features['flow_id']} prediction completed with prediction: {prediction[0]}.\n")

    return result
  
  def run(self, local_packet_queue: Queue, log_writer_queue: Queue, finished_flow_queue: Queue, stop_processing: Event, thread_finished: Event):
    while not stop_processing.is_set():
      if not local_packet_queue.empty():
        packet = local_packet_queue.get()
        to_log = []
        timeout_flows = self.search_ended_flows()
        current_flow_finished = self.add_packet_to_flow(packet)
        
        if current_flow_finished is not None:
          # flow is finished and we need to create new flow for the received packet
          flow = self.ongoing_flows.pop(current_flow_finished)
          self.add_packet_to_flow(packet)
          finished_flow_queue.put(current_flow_finished)
          to_log.append(self.predict_flow(flow))
          # print(f"Flow {current_flow_finished} is finished.")
        
        for flow_id in timeout_flows:
          if flow_id == current_flow_finished:
            continue
          flow = self.ongoing_flows.pop(flow_id)
          finished_flow_queue.put(flow_id)
          to_log.append(self.predict_flow(flow))
          # print(f"Flow {flow_id} is timeout.")

        for log in to_log:
          log_writer_queue.put(log)

    self.finish_jobs(local_packet_queue, log_writer_queue, finished_flow_queue)
    print("NetworkFlowHandler thread is finished.")
    # send signal to main program that this thread is finished
    thread_finished.set()

  def add_packet_to_flow(self, packet: Packet):
    flow_id, alt_flow_id = packet.get_flow_id()

    flow = None
    if flow_id in self.ongoing_flows:
      flow = self.ongoing_flows[flow_id]
    elif alt_flow_id in self.ongoing_flows:
      flow = self.ongoing_flows[alt_flow_id]
      flow_id = alt_flow_id

    if flow is None:
      flow = Flow(packet, self.timeout)
      self.ongoing_flows[str(flow)] = flow
      # print(f"Created new flow: {str(flow)}")
      return
    else:
      if self.is_finished_flow(flow, packet):
        return flow_id
      flow.add_packet(packet)

  def search_ended_flows(self):
    ended_flows = []
    for flow in self.ongoing_flows.values():
      if self.is_timeout_flow(flow):
        ended_flows.append(str(flow))
    return ended_flows

  def is_timeout_flow(self, flow: Flow):
    flow_duration = datetime.now() - datetime.fromtimestamp(float(flow.get_flow_start_time()))
    active_time = datetime.now() - datetime.fromtimestamp(float(flow.get_flow_last_seen()))
    if flow_duration.total_seconds() > self.config.max_flow_duration \
      or active_time.total_seconds() > self.config.activity_timeout:
      return True
    return False

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
  
  def finish_jobs(self, local_packet_queue: Queue, log_writer_queue: Queue, finished_flow_queue: Queue):
    while not local_packet_queue.empty():
      packet = local_packet_queue.get()
      to_log = []
      timeout_flows = self.search_ended_flows()
      current_flow_finished = self.add_packet_to_flow(packet)
      
      if current_flow_finished is not None:
        # flow is finished and we need to create new flow for the received packet
        flow = self.ongoing_flows.pop(current_flow_finished)
        self.add_packet_to_flow(packet)
        finished_flow_queue.put(current_flow_finished)
        to_log.append(self.predict_flow(flow))
        # print(f"Flow {current_flow_finished} is finished.")
      
      for flow_id in timeout_flows:
        if flow_id == current_flow_finished:
          continue
        flow = self.ongoing_flows.pop(flow_id)
        finished_flow_queue.put(flow_id)
        to_log.append(self.predict_flow(flow))
        # print(f"Flow {flow_id} is timeout.")

      for log in to_log:
        log_writer_queue.put(log)
