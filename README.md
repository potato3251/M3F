# M3F: A Novel Multi-Session and Multi-Protocol Based Malware Traffic Fingerprinting

## Prerequisites

1. install Zeek https://docs.zeek.org/


## build fingerprint

1. parse pcap
```shell
zeek -r <pcap_filename> LogAscii::use_json=T
```
2. Move the traffic log of a malware to a folder
```shell
mkdir yakes
mv *.log yakes
```
3. build fingerprint
```shell
py train.py --input ./yakes/ --output yakes.fp
```
