import os

import numpy as np
from scapy.all import *


class Flow:
    def __init__(self):
        self.flow_id = ""
        self.bwd_flow_id = ""
        self.pkt_list = []
        self.start_ts = 0
        self.pkt_cnt = 0

        # 只针对TCP数据包
        self.first_FIN = False
        self.second_FIN = False

    def add_first_pkt(self, pkt):
        proto = f"{pkt[1].proto}" if pkt[1].proto in [6, 17] else "0"  # 仅识别TCP、UDP，其他协议置为0
        
        # 生成正反流的id
        self.flow_id = f"{pkt[1].src}-{pkt[1].dst}-{pkt[1].sport}-{pkt[1].dport}-" + proto
        self.bwd_flow_id = f"{pkt[1].dst}-{pkt[1].src}-{pkt[1].dport}-{pkt[1].sport}-" + proto

        # 设置流开始的时间戳
        self.start_ts = pkt.time

        # 把包加入流中
        self.add_pkt(pkt)

    def add_pkt(self, pkt):
        """把包加入流中"""
        self.pkt_list.append(self.wash_pkt(pkt))
        self.pkt_cnt += 1

    @staticmethod
    def wash_pkt(pkt):
        pkt[0].src = "00:00:00:00:00:00"
        pkt[0].dst = "00:00:00:00:00:00"
        pkt[1].src = "0.0.0.0"
        pkt[1].dst = "0.0.0.0"
        pkt[1].chksum = 0
        pkt[2].chksum = 0
        return pkt

    def dump(self, output_dir, dump="pcap"):
        if dump == "pcap":
            self.dump_pcap(output_dir)
        elif dump == "npz":
            self.dump_npz(output_dir)
        else:
            raise AttributeError("Wrong dump way", dump)

    def dump_pcap(self, output_dir):
        wrpcap(os.path.join(output_dir, self.flow_id+".pcap"), self.pkt_list)

    def dump_npz(self, output_dir):
        arrays = [np.array(bytes(pkt)) for pkt in self.pkt_list]
        np.savez(os.path.join(output_dir, self.flow_id+".npz"), *arrays)

    def __len__(self):
        return self.pkt_cnt
