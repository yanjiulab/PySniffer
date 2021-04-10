from packet_sniffer import *
import logging
import os
import signal
import time
from multiprocessing import Process


def func(**kwargs):
    f = PacketFilter(proto_type='tcp')
    print(kwargs)
    sniffer = PacketSniffer(**kwargs)
    sniffer.sniff()


if __name__ == "__main__":
    p = None

    kwargs = {'limit': 10000, 'pcap_by_session': False,
              'pcap_dir': 'pcap/'}

    kwargs['packet_filter'] = PacketFilter(proto_type='tcp')

    if not p:
        p = Process(target=func, kwargs=kwargs)
    p.start()
    time.sleep(10)
    os.kill(p.pid, signal.SIGINT)

    #
    # pid = os.fork()
    # if pid == 0:
    #     print('I am child process (%s) and my parent is %s.' % (os.getpid(), os.getppid()))
    #     child_pid = os.getpid()
    #     f = PacketFilter(proto_type='tcp')
    #     sniffer = PacketSniffer(limit=100, packet_filter=f, pcap_enable=True, pcap_by_session=False,
    #                             log_level=logging.DEBUG)
    #     sniffer.sniff()
    # else:
    #     # ....
    #
    #     print('I (%s) just created a child process (%s).' % (os.getpid(), pid))
    #     time.sleep(5)
    #     os.kill(pid, signal.SIGINT)
