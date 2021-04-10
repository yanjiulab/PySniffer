# PySniffer
A simple packet sniffer written by Python (Linux only)

Supported packet type:
- sniff IP packet
- sniff IP packet
- sniff IP packet

## Features
- Sniff all packet by raw socket
- Customize filtering rules via socket tuple(src_ip, dst_ip, src_port, dst_port, proto_type)
- Store the data by session


## Classes
- PacketSniffer: Sniffing packet
- PacketFilter: Customizing filter rule used by sniffer
- Pcap: Storing the packet in pcap file


## Usage
1. copy the package `packet_sniffer` to your own project
2. import package and use

example use case:
```python
from packet_sniffer import *
f = PacketFilter(proto_type='udp')
sniffer = PacketSniffer(limit=10, packet_filter=f, pcap_enable=True)
sniffer.sniff()
``` 
