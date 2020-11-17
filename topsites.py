import os
import sys
import py
import re
import csv
import pyshark
import itertools
from tabulate import tabulate

tw = py.io.TerminalWriter()


def pretty_print(dictionary, count):
    if len(dictionary) > 0:
        tw.write("Top "+str(count)+" websites\n\n", yellow=True, bold=True)
        if len(dictionary) > count:
            top_sites = [entry for entry in itertools.islice(
                dictionary.values(), count)]
        else:
            top_sites = list(dictionary.values())
        headings = ['server_ip', 'server_port', 'protocol',
                    'server_packet_count', 'client_packet_count', 'total_packets', 'domain_name']
        table = []
        rank = 1
        for site in top_sites:
            if len(site) > 0:
                row = [rank]
                for heading in headings:
                    if heading in site:
                        row.append(site[heading])
                    else:
                        row.append('')
                table.append(row)
                rank += 1
        headings.insert(0, 'rank')
        print(tabulate(table, headings, tablefmt="pretty"))
    else:
        tw.write("No HTTP and HTTPS packets found.\n", yellow=True)


def sort(dictionary):
    for entry in dictionary.values():
        entry['total_packets'] = entry['server_packet_count'] + \
            entry['client_packet_count']
    sorted_dictionary = {key: value for key, value in sorted(
        dictionary.items(), key=lambda item: item[1]['total_packets'], reverse=True)}
    return sorted_dictionary


def process(path, mode):
    conversations = {}
    headers = ['Source', 'Source port', 'Destination',
               'Destination Port', 'Protocol', 'Info', 'Domain Name']
    if mode == 'pcap':
        display_filter = "tls or http"
        capture = pyshark.FileCapture(path, display_filter=display_filter)
        for packet in capture:
            if 'HTTP' in packet:
                if 'request_version' in packet.http.field_names:
                    server_ip = str(packet.ip.dst)
                    server_port = str(packet.tcp.dstport)
                    ip_port_key = server_ip+':'+server_port
                    if ip_port_key not in conversations:
                        entry = {
                            'server_ip': server_ip,
                            'server_port': server_port,
                            'protocol': 'http',
                            'server_packet_count': 0,
                            'client_packet_count': 1,
                            'domain_name': str(packet.http.host)
                        }
                        conversations[ip_port_key] = entry
                    else:
                        conversations[ip_port_key]['client_packet_count'] += 1
                elif 'response_version' in packet.http.field_names:
                    server_ip = str(packet.ip.src)
                    server_port = str(packet.tcp.srcport)
                    ip_port_key = server_ip+':'+server_port
                    if ip_port_key in conversations:
                        conversations[ip_port_key]['server_packet_count'] += 1
            elif 'TLS' in packet:
                src_ip = str(packet.ip.src)
                dst_ip = str(packet.ip.dst)
                src_port = str(packet.tcp.srcport)
                dst_port = str(packet.tcp.dstport)
                src_key = src_ip+':'+src_port
                dst_key = dst_ip+':'+dst_port
                if 'record' in packet.tls.field_names:
                    expression = ".*Handshake Protocol: Client Hello.*"
                    if re.search(expression, packet.tls.record):
                        if dst_key not in conversations:
                            entry = {
                                'server_ip': dst_ip,
                                'server_port': dst_port,
                                'protocol': 'https',
                                'server_packet_count': 0,
                                'client_packet_count': 1
                            }
                            if 'handshake_extensions_server_name' in packet.tls.field_names:
                                entry['domain_name'] = packet.tls.handshake_extensions_server_name
                            conversations[dst_key] = entry
                        else:
                            conversations[dst_key]['client_packet_count'] += 1
                    else:
                        if dst_key in conversations:
                            conversations[dst_key]['client_packet_count'] += 1
                        elif src_key in conversations:
                            conversations[src_key]['server_packet_count'] += 1
    else:
        with open(path) as f:
            csv_reader = csv.DictReader(f)

            # Testing valid configuration
            for row in csv_reader:
                for name in headers:
                    if name not in row:
                        return False, conversations
                break

    return True, conversations


if __name__ == '__main__':
    if len(sys.argv) != 2:
        tw.write("Usage: python3 topsites.py [path-to-file]\n", red=True)
        exit(2)
    path = sys.argv[1]
    if not (os.path.exists(path) and os.path.isfile(path)):
        tw.write("File not found\n", red=True)
        exit(1)
    parts = list(os.path.basename(path).split('.', 1))
    if len(parts) != 2 or (parts[1] != 'pcap' and parts[1] != 'csv'):
        tw.write(
            "Mode not supported.\nSupported modes are pcap and csv.\n", yellow=True)
        exit(1)
    mode = parts[1]
    success, dictionary = process(path, mode)
    if success:
        dictionary = sort(dictionary)
        pretty_print(dictionary, 3)
    else:
        tw.write(
            "Invalid configuration. Refer https://github.com/wistic/packet-analysis/blob/main/README.md for more details.\n", red=True)
        exit(1)
