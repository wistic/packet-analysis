import pyshark
import sys
import os
import re
import py


if __name__ == "__main__":
    tw = py.io.TerminalWriter()
    if len(sys.argv) != 2:
        print("Usage: python3 sniffer.py [path-to-pcap-file]")
        exit(2)
    path = sys.argv[1]
    if not (os.path.exists(path) and os.path.isfile(path)):
        print("File not found")
        exit(1)

    # HTTP sniffing
    display_filter = "http.request.method == POST"
    capture = pyshark.FileCapture(path, display_filter=display_filter)
    for packet in capture:
        # Forms are generally in application/x-www-urlencoded
        if 'HTTP' in packet and packet.highest_layer == "URLENCODED-FORM":
            form_layer = packet['urlencoded-form']
            is_useful = False
            for field_line in form_layer._get_all_field_lines():
                if re.search(".*[pP]assword.*", field_line):
                    is_useful = True
            if is_useful:
                tw.write("HTTP data for ",
                         yellow=True, bold=True)
                tw.write(packet.http.request_full_uri +
                         "\n", red=True, bold=True)
                for field_line in form_layer._get_all_field_lines():
                    if ':' in field_line:
                        field_name, field_line = field_line.split(':', 1)
                        if re.search('^Key', field_name.strip('\t')):
                            tw.write('\t'+field_line.strip('\n') +
                                     ':', green=True, bold=True)
                        elif re.search('^Value', field_name.strip('\t')):
                            tw.write(field_line, bold=True)
    capture.close()

    # FTP sniffing
    display_filter = "(ftp.request.command == USER or ftp.request.command == PASS)"
    capture = pyshark.FileCapture(path, display_filter=display_filter)
    conversations = {}
    for packet in capture:
        if "FTP" in packet:
            ip_address = packet['ip'].dst
            port = packet.tcp.dstport
            ip_port_key = str(ip_address)+":"+str(port)
            if ip_port_key not in conversations:
                conversation_dict = {
                    "ip": str(ip_address),
                    "port": str(port)
                }
                if packet.ftp.request_command == "USER":
                    conversation_dict['user'] = str(packet.ftp.request_arg)
                elif packet.ftp.request_command == "PASS":
                    conversation_dict['password'] = str(packet.ftp.request_arg)
                conversations[ip_port_key] = conversation_dict
            else:
                conversation_dict = conversations[ip_port_key]
                if packet.ftp.request_command == "USER":
                    conversation_dict['user'] = str(packet.ftp.request_arg)
                elif packet.ftp.request_command == "PASS":
                    conversation_dict['password'] = str(packet.ftp.request_arg)
    capture.close()

    display_filter = "dns"
    capture = pyshark.FileCapture(path, display_filter=display_filter)
    ip_search_space = set([key.split(":", 1)[0]
                           for key in conversations.keys()])
    for packet in capture:
        if "DNS" in packet and int(packet.dns.flags_response) == 1 and int(packet.dns.qry_type) == 1:
            if int(packet.dns.count_answers) == 1 and int(packet.dns.resp_type) == 1 and str(packet.dns.a) in ip_search_space:
                fqdn = str(packet.dns.resp_name)
                for ip_port_key in conversations.keys():
                    if ip_port_key.startswith(str(packet.dns.a)):
                        conversations[ip_port_key]['fqdn'] = fqdn

    capture.close()

    tw.write("FTP Credential Dump\n", yellow=True, bold=True)
    count = 1
    for entry in conversations.values():
        tw.write("Entry "+str(count)+"\n", red=True, bold=True)
        count += 1
        for key, value in entry.items():
            tw.write('\t'+key+':', green=True, bold=True)
            tw.write(value+'\n', bold=True)
