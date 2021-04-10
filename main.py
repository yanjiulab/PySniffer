from packet_sniffer import *
import logging

if __name__ == "__main__":
    f = PacketFilter(proto_type='tcp')
    sniffer = PacketSniffer(limit=20, packet_filter=f, pcap_enable=True, pcap_by_session=False, log_level=logging.DEBUG)
    sniffer.sniff()
