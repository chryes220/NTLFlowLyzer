#!/usr/bin/env python3

import argparse
import glob

from NTLFlowLyzer.config_loader import ConfigLoader
from .network_flow_analyzer import NTLFlowLyzer
from .live_network_sniffer import LiveNetworkSniffer

def args_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='NTLFlowLyzer')
    parser.add_argument('-c', '--config-file', action='store', help='Json config file address.')
    parser.add_argument('-o', '--online-capturing', action='store_true',
                        help='Capturing mode. The default mode is offline capturing.')
    parser.add_argument('-b', '--batch-mode', action='store_true',
                        help='Analyze all the files in the given directory. The default is False.')
    parser.add_argument('-cb', '--continues-batch-mode', action='store_true',
                        help='Continues batch mode. Analyze files in the given directory continuously.'
                            ' Default is False.')
    parser.add_argument('-i', '--interface', action='store', help='Network interface name for live capturing.')
    parser.add_argument('-m', '--model', action='store', choices=['xgb-no-bot', 'xgb-no-dos-hulk', 'xgb-no-dos-slowloris', 'xgb-no-heartbleed', 'oc-svm'], 
                        help='Model name for the classification.\nOptions: xgb-no-bot, xgb-no-dos-hulk, xgb-no-dos-slowloris, xgb-no-heartbleed, oc-svm')
    parser.add_argument('-d', '--run-as-daemon', action='store_true', help='Run the program as a daemon.')
    return parser


def find_pcap_files(directory):
    file_pattern = directory + '/*'
    pcap_files = glob.glob(file_pattern)
    return pcap_files


def main():
    print("You initiated NTLFlowLyzer!")
    parsed_arguments = args_parser().parse_args()
    config_file_address = "./NTLFlowLyzer/config.json" if parsed_arguments.config_file is None else parsed_arguments.config_file
    online_capturing = parsed_arguments.online_capturing
    interface = parsed_arguments.interface
    model = parsed_arguments.model

    if interface is not None:
        print(">> Interface is specified. Going for live capturing!")
        config = ConfigLoader(config_file_address)
        live_network_sniffer = LiveNetworkSniffer(interface, config, model)
        live_network_sniffer.run()
        return
    
    if not parsed_arguments.batch_mode:
        config = ConfigLoader(config_file_address)
        network_flow_analyzer = NTLFlowLyzer(config, parsed_arguments.continues_batch_mode)
        network_flow_analyzer.run()
        return

    print(">> Batch mode is on!")
    config = ConfigLoader(config_file_address)
    batch_address = config.batch_address
    batch_address_output = config.batch_address_output
    pcap_files = find_pcap_files(batch_address)
    print(f">> {len(pcap_files)} number of files detected. Lets go for analyze them!")
    for file in pcap_files:
        print(100*"#")
        output_file_name = file.split('/')[-1]
        config.pcap_file_address = file
        config.output_file_address = f"{batch_address_output}/{output_file_name}.csv"
        network_flow_analyzer = NTLFlowLyzer(config, parsed_arguments.continues_batch_mode)
        network_flow_analyzer.run()


if __name__ == "__main__":
    main()
