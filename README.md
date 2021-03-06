## Packet Analysis
### Modules
- [__`sniffer`__](https://github.com/wistic/packet-analysis/blob/main/sniffer.py): Use to extract sensitive data such as username and passwords from `pcap` files. It can be used to test the strength of various networking protocols.
- [__`topsites`__](https://github.com/wistic/packet-analysis/blob/main/topsites.py): Use to find the most visited websites from ___Wireshark pcap dump___ or ___csv packet dissections___. It can be used by network administrators to find out the most visited websites in their organization.
### To run locally
1. Clone the github repository.
```shell
$ git clone https://github.com/wistic/packet-analysis.git
```
2. Create a [virtualenv](https://pypi.org/project/virtualenv/).
```shell
$ cd packet-analysis
$ virtualenv venv
$ source venv/bin/activate
```
3. Install the requirements.
```shell
$ pip install -r requirements.txt
```
4. Install [__Wireshark__](https://www.wireshark.org/download.html) and [__tshark__](https://tshark.dev/setup/install/).
5. Add [topsites](https://github.com/wistic/packet-analysis/tree/main/config/topsites) to your [Wireshark configuration profiles](https://www.wireshark.org/docs/wsug_html_chunked/ChCustConfigProfilesSection.html).
6. Run
    - To run __sniffer__:
    ```shell
    $ python sniffer.py [path-to-pcap-file]
    ```
    - To run __topsites__:
    ```shell
    $ python topsites.py [path-to-file]
    ```
### Note
- Make sure tshark is installed in one of the paths mentioned in this [config file](https://github.com/KimiNewt/pyshark/blob/master/src/pyshark/config.ini).
- Download sample pcap and csv files from [here](https://drive.google.com/drive/folders/1TBTElE37t24a31X-ZC7bpok_izmpn_1i?usp=sharing).
- Only use the [topsites](https://github.com/wistic/packet-analysis/tree/main/config/topsites) configuration profile to [export packet dissections](https://www.wireshark.org/docs/wsug_html_chunked/ChIOExportSection.html).
- It is advised  to use the display filter `ip and tcp and (tls or http)` before exporting packet dissections to remove usless packets from the csv dump.
- Supported file formats for topsites are `pcap` and `csv`.
- Supported file format for sniffer is `pcap`.