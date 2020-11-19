import pyshark
import sys
import os
import re
import py

tw = py.io.TerminalWriter()


def pretty_print(protocol, dictionary):
    if len(dictionary) > 0:
        tw.write(protocol.upper()+" Credential Dump\n", yellow=True, bold=True)
    count = 1
    for entry in dictionary.values():
        tw.write("Entry "+str(count)+"\n", red=True, bold=True)
        count += 1
        for key, value in entry.items():
            tw.write('\t'+key+':', green=True, bold=True)
            tw.write(value+'\n', bold=True)


def dns_search(dictionary, path):
    display_filter = "dns"
    capture = pyshark.FileCapture(path, display_filter=display_filter)
    ip_search_space = set([key.split(":", 1)[0]
                           for key in dictionary.keys()])
    for packet in capture:
        if "DNS" in packet and int(packet.dns.flags_response) == 1 and int(packet.dns.qry_type) == 1:
            if int(packet.dns.count_answers) == 1 and int(packet.dns.resp_type) == 1 and str(packet.dns.a) in ip_search_space:
                fqdn = str(packet.dns.resp_name)
                for ip_port_key in dictionary.keys():
                    if ip_port_key.startswith(str(packet.dns.a)):
                        dictionary[ip_port_key]['fqdn'] = fqdn
    capture.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        tw.write("Usage: python3 sniffer.py [path-to-pcap-file]\n", red=True)
        exit(2)
    path = sys.argv[1]
    if not (os.path.exists(path) and os.path.isfile(path)):
        tw.write("File not found\n", red=True)
        exit(1)
    parts = list(os.path.basename(path).split('.', 1))
    if len(parts) != 2 or parts[1] != 'pcap':
        tw.write(
            "Mode not supported.\nCurrently supported mode is pcap.\n", yellow=True)
        exit(1)

    # HTTP sniffing
    display_filter = "http.request.method == POST"
    capture = pyshark.FileCapture(path, display_filter=display_filter)
    http_conversations = dict()
    for packet in capture:
        # Forms are generally in application/x-www-urlencoded
        if 'HTTP' in packet and packet.highest_layer == "URLENCODED-FORM":
            form_layer = packet['urlencoded-form']
            is_useful = False
            for field_line in form_layer._get_all_field_lines():
                if re.search(".*[pP]assword.*", field_line):
                    is_useful = True
            if is_useful:
                url = packet.http.request_full_uri
                if url not in http_conversations:
                    conversation = {
                        'fqdn': url,
                        'ip': packet.ip.dst,
                        'port': packet.tcp.dstport
                    }
                    http_conversations[url] = conversation
                else:
                    conversation = http_conversations[url]

                for field_line in form_layer._get_all_field_lines():
                    if ':' in field_line:
                        field_name, field_line = field_line.split(':', 1)
                        if re.search('^Form item', field_name.strip()):
                            key, value = field_line.split('=', 1)
                            key = key.strip().strip('\"')
                            value = value.strip().strip('\"')
                            if key != "" and value != "":
                                conversation[key] = value

    capture.close()
    pretty_print('http', http_conversations)

    # FTP sniffing
    display_filter = "(ftp.request.command == USER or ftp.request.command == PASS)"
    capture = pyshark.FileCapture(path, display_filter=display_filter)
    ftp_conversations = dict()
    for packet in capture:
        if "FTP" in packet:
            ip_address = packet.ip.dst
            port = packet.tcp.dstport
            ip_port_key = str(ip_address)+":"+str(port)
            if ip_port_key not in ftp_conversations:
                conversation = {
                    "ip": str(ip_address),
                    "port": str(port)
                }
                ftp_conversations[ip_port_key] = conversation
            else:
                conversation = ftp_conversations[ip_port_key]

            if packet.ftp.request_command == "USER":
                conversation['user'] = str(packet.ftp.request_arg)
            elif packet.ftp.request_command == "PASS":
                conversation['password'] = str(packet.ftp.request_arg)
    capture.close()

    dns_search(ftp_conversations, path)
    pretty_print('ftp', ftp_conversations)

    # Telnet sniffing
    display_filter = "telnet and telnet.data"
    capture = pyshark.FileCapture(path, display_filter=display_filter)
    telnet_conversations = dict()
    begin = False
    key = ""
    value = ""
    client_ip = ""
    server_ip = ""
    for packet in capture:
        if begin and str(packet.ip.src) == client_ip and str(packet.ip.dst) == server_ip:
            for field_line in packet.telnet._get_all_field_lines():
                if re.search(r".*Data: \\r.*", field_line):
                    begin = False
            if begin:
                value += packet.telnet.data
            else:
                port = packet.tcp.dstport
                ip_port_key = str(server_ip)+":"+str(port)
                if ip_port_key not in telnet_conversations:
                    conversation = {
                        "ip": str(server_ip),
                        "port": str(port)
                    }
                    telnet_conversations[ip_port_key] = conversation
                else:
                    conversation = telnet_conversations[ip_port_key]

                if key != "":
                    conversation[key] = value
                key = value = client_ip = server_ip = ""
        else:
            expression = ".*[lL]ogin:.*"
            pwd_expression = "[pP]assword: "
            for field_line in packet.telnet._get_all_field_lines():
                if re.search(expression, field_line):
                    begin = True
                    key = "user"
                    client_ip = str(packet.ip.dst)
                    server_ip = str(packet.ip.src)
                if re.search(pwd_expression, field_line):
                    begin = True
                    key = "password"
                    client_ip = str(packet.ip.dst)
                    server_ip = str(packet.ip.src)

    capture.close()

    dns_search(telnet_conversations, path)
    pretty_print('telnet', telnet_conversations)
