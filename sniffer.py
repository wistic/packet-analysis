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
    capture = pyshark.FileCapture(path)
    count = 0
    for packet in capture:
        # Forms are generally in application/x-www-urlencoded
        if 'HTTP' in packet and packet.highest_layer == "URLENCODED-FORM":
            form_layer = packet['urlencoded-form']
            is_useful = False
            for field_line in form_layer._get_all_field_lines():
                if re.search(".*[pP]assword.*", field_line):
                    is_useful = True
            if is_useful:
                tw.write("Form data for ",
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
