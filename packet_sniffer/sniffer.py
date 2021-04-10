# Packet sniffer in python
# For Linux - Sniffs all incoming and outgoing packets :)
# Copyright Silver Moon (m00n.silv3r@gmail.com)
# Modified by Yanjiu Lab

import os
import socket
import sys
import itertools
import struct
import logging
import time
import signal
import shutil
from datetime import datetime

from .pcap import Pcap
from .filter import PacketFilter


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
    return b


def looper(limit):
    """Return an optionally endless list of indexes."""
    if limit is not None:
        return range(limit)
    return itertools.count()


def config_logger(log_level):
    # create logger
    logger = logging.getLogger(PacketSniffer.__name__)
    logger.setLevel(log_level)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)  # create console handler and set level to debug
    fh = logging.FileHandler('file.log')
    fh.setLevel(logging.INFO)  # create file handler and set level to info

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    logger.addHandler(ch)
    logger.addHandler(fh)

    return logger


class PacketSniffer:
    def __init__(self, limit=10000, elapsed_time_max=10000,
                 packet_filter: PacketFilter = None,
                 log_level=logging.DEBUG,
                 pcap_enable=True, pcap_dir='pcap/', pcap_by_session=True, pcap_clear_dir=True):
        """

        :param limit: maximum packet number
        :param elapsed_time_max: maximum time elapsed
        :param packet_filter: packet filter
        :param log_level: log level, DEBUG by default
        :param pcap_enable: store data or not
        :param pcap_dir: directory of pcap files
        :param pcap_by_session: store data by session or not
        :param pcap_clear_dir: clear directory of pcap or not
        """

        self.limit = limit  # sniff by packet number
        self.elapsed_time_max = elapsed_time_max  # sniff by time
        self.start_time = datetime.now()

        self.filter = packet_filter
        self.logger = config_logger(log_level)
        self.pcap_enable = pcap_enable
        self.pcap_dir = pcap_dir
        self.pcap_by_session = pcap_by_session
        self.pcap_clear_dir = pcap_clear_dir

        self.pcap = None
        self.curr_packet_tuple = []

        self.ip_packet_num = 0
        self.tcp_packet_num = 0
        self.udp_packet_num = 0

    def sniff(self):
        # promote privilege
        euid = os.geteuid()
        if euid != 0:
            self.logger.info('ATTENTION PLEASE: Packet Sniffer not started as root. Running sudo...')
            args = ['sudo', '-S', sys.executable] + sys.argv + [os.environ]
            os.execlpe('sudo', *args)

        self.logger.info('Packet Sniffer running as root!')

        # create a AF_PACKET type raw socket
        # define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.ntohs(0x0003))
        except OSError as e:
            logging.error('Socket could not be created. Error Code : %s ', e)
            sys.exit()

        # init
        if self.pcap_clear_dir:
            shutil.rmtree(self.pcap_dir)  # 能删除该文件夹和文件夹下所有文件
            os.mkdir(self.pcap_dir)

        # receive a packet
        signal.signal(signal.SIGINT, signal.default_int_handler)
        try:
            while self.limit:
                # calculate time
                current_time = datetime.now()
                elapsed_time = (current_time - self.start_time).seconds
                if elapsed_time > self.elapsed_time_max:
                    break

                # init
                self.curr_packet_tuple.clear()

                # capture
                packet = s.recvfrom(65535)
                packet = packet[0]  # packet string from tuple

                # parse mac
                eth_length = 14  # parse ethernet header
                eth_header = packet[:eth_length]
                eth = struct.unpack('!6s6sH', eth_header)
                eth_protocol = socket.ntohs(eth[2])
                self.logger.debug('Destination MAC : %s, Source MAC : %s, Protocol : %s',
                                  eth_addr(packet[0:6]), eth_addr(packet[6:12]), str(eth_protocol))

                # Parse IP packets, IP Protocol number = 8
                if eth_protocol == 8:
                    # Parse IP header
                    # take first 20 characters for the ip header
                    ip_header = packet[eth_length:20 + eth_length]

                    # now unpack them :)
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

                    version_ihl = iph[0]
                    version = version_ihl >> 4
                    ihl = version_ihl & 0xF

                    iph_length = ihl * 4

                    ttl = iph[5]
                    protocol = iph[6]
                    s_addr = socket.inet_ntoa(iph[8])
                    d_addr = socket.inet_ntoa(iph[9])

                    # filter
                    if self.filter:
                        if self.filter.src_ip and self.filter.src_ip != str(s_addr):
                            continue
                        if self.filter.dst_ip and self.filter.dst_ip != str(d_addr):
                            continue
                        if self.filter.proto_type:
                            if self.filter.proto_type == 'tcp' and protocol != 6:
                                continue
                            elif self.filter.proto_type == 'udp' and protocol != 17:
                                continue

                    self.curr_packet_tuple.append(str(s_addr))
                    self.curr_packet_tuple.append(str(d_addr))
                    self.curr_packet_tuple.append(protocol)

                    self.ip_packet_num += 1
                    self.logger.debug(
                        'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) +
                        ' Protocol : ' + str(protocol) + ' Source Address : ' + str(
                            s_addr) + ' Destination Address : ' + str(d_addr))

                    # TCP protocol
                    if protocol == 6:
                        t = iph_length + eth_length
                        tcp_header = packet[t:t + 20]

                        # now unpack them :)
                        tcph = struct.unpack('!HHLLBBHHH', tcp_header)

                        source_port = tcph[0]
                        dest_port = tcph[1]
                        sequence = tcph[2]
                        acknowledgement = tcph[3]
                        doff_reserved = tcph[4]
                        tcph_length = doff_reserved >> 4

                        # filtering
                        if self.filter:
                            if self.filter.src_port and self.filter.src_port != str(source_port):
                                continue
                            if self.filter.dst_port and self.filter.dst_port != str(dest_port):
                                continue

                        self.curr_packet_tuple.append(source_port)
                        self.curr_packet_tuple.append(dest_port)

                        self.logger.debug(
                            'Source Port : ' + str(source_port) + ' Destination Port : ' + str(
                                dest_port) + ' Sequence Number : ' +
                            str(sequence) + ' Acknowledgement : ' + str(
                                acknowledgement) + ' TCP header length : ' + str(
                                tcph_length))

                        h_size = eth_length + iph_length + tcph_length * 4
                        data_size = len(packet) - h_size

                        # get data from the packet
                        data = packet[h_size:]
                        self.logger.debug('Data : ' + str(data))

                        self.tcp_packet_num += 1

                    # UDP packets
                    elif protocol == 17:
                        u = iph_length + eth_length
                        udph_length = 8
                        udp_header = packet[u:u + 8]

                        # now unpack them :)
                        udph = struct.unpack('!HHHH', udp_header)

                        source_port = udph[0]
                        dest_port = udph[1]
                        length = udph[2]
                        checksum = udph[3]

                        self.logger.debug('Source Port : ' + str(source_port) + ' Dest Port : ' +
                                          str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))

                        h_size = eth_length + iph_length + udph_length
                        data_size = len(packet) - h_size

                        # get data from the packet
                        data = packet[h_size:]
                        self.logger.debug('Data : ' + str(data))

                        self.udp_packet_num += 1

                    # some other IP packet like IGMP
                    else:
                        continue
                else:
                    continue

                # save to pcap file
                if self.pcap_enable:
                    if self.pcap_by_session:
                        filename = self.pcap_dir + '_'.join(sorted([str(s) for s in set(self.curr_packet_tuple)]))
                        self.pcap = Pcap(filename=filename)
                        self.pcap.write(packet)
                        self.pcap.pcap_file.flush()  # flush data
                        self.pcap.pcap_file.close()
                    else:
                        filename = time.strftime(self.pcap_dir + "%y%m%d-%H%M")
                        self.pcap = Pcap(filename=filename)
                        self.pcap.write(packet)
                        self.pcap.pcap_file.flush()  # flush data

                # update index
                self.limit -= 1
        except KeyboardInterrupt:
            if not self.pcap_by_session:
                self.pcap.pcap_file.close()
            self.logger.info('Sniffer Interrupted!')
            sys.exit()
        finally:
            self.logger.info('Sniffer finished ...')
            self.logger.info('Statistics: IP Packet : %s, TCP Packet : %s, UDP Packet : %s',
                             self.ip_packet_num, self.tcp_packet_num, self.udp_packet_num)

    # def handler_stop_signals(self, signum, frame):
    #     self.limit = 0
