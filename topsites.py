import pyshark
import os
import sys
import py

tw = py.io.TerminalWriter()

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
