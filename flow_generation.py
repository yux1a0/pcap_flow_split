from scapy.all import *
from scapy.layers.inet import IP, TCP

from flow import Flow


class FlowGeneration:
    def __init__(self, source, dump="pcap", output_dir="pcap_s", flow_max_duration=1800, count=-1):
        """
        source: pcap文件路径
        dump: 数据包导出方式（pcap or npz）
        output_dir: 导出路径
        flow_max_duration: 流的最大超时时间，单位秒
        count: 从pcap文件中读取数据包的数量，-1表示所有
        """
        self.source = source
        self.dump = dump
        self.output_dir = output_dir
        self.flow_max_duration = flow_max_duration
        self.count = count

        if not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)

        # 流统计信息
        self.flow_total_cnt = 0
        self.current_flow_cnt = 0
        self.dumped_flow_cnt = 0
        # 数据包统计信息
        self.processed_pkt_cnt = 0
        self.droped_pkt_cnt = 0

        self.flows_dict = dict()

    @staticmethod
    def hash_pkt(pkt):
        p = 1000000000003

        def ip_to_int(x):
            return sum([256**j*int(i) for j, i in enumerate(x.split('.')[::-1])])
        if pkt.proto not in [6, 17]:
            return ((ip_to_int(pkt[1].src) * pkt[1].sport) % p + (ip_to_int(pkt[1].dst) * pkt[1].dport) % p + 0) % p
        return ((ip_to_int(pkt[1].src) * pkt[1].sport) % p + (ip_to_int(pkt[1].dst) * pkt[1].dport) % p + pkt[1].proto) % p

    def create_new_flow(self, hash, pkt):
        if TCP in pkt:
            if 'S' in pkt[TCP].flags:
                # SYN才是TCP流的开始
                tmp_flow = Flow()
                tmp_flow.add_first_pkt(pkt)
                self.flows_dict[hash] = tmp_flow

                self.current_flow_cnt += 1
                self.flow_total_cnt += 1
            else:
                self.droped_pkt_cnt += 1
        else:
            # 对于UDP或其他协议，不需要进行上述的判断
            tmp_flow = Flow()
            tmp_flow.add_first_pkt(pkt)
            self.flows_dict[hash] = tmp_flow

            self.current_flow_cnt += 1
            self.flow_total_cnt += 1

    def dump_flow(self, hash):
        print(self.flows_dict[hash].flow_id)
        self.flows_dict[hash].dump(self.output_dir, self.dump)
        del self.flows_dict[hash]
        self.current_flow_cnt -= 1
        self.dumped_flow_cnt += 1

    def check_TCP_FIN(self, hash, pkt):
        if TCP in pkt:
            if 'F' in pkt[TCP].flags:  # 存在FIN标志位
                if not self.flows_dict[hash].first_FIN:  # 第一个FIN
                    self.flows_dict[hash].first_FIN = True
                    return True
                elif not self.flows_dict[hash].second_FIN:  # 第二个FIN
                    self.flows_dict[hash].second_FIN = True
                    return True
                else:  # 更多的FIN
                    return False
            # 不存在FIN，但是两个FIN都出现过了
            elif self.flows_dict[hash].first_FIN and self.flows_dict[hash].second_FIN:
                if pkt[TCP].flags == 'A':  # 如果是最后一个ACK，可以接受
                    return True
                else:
                    return False
            else:  # 不存在FIN，且未出现过两次FIN，接受
                return True
        return True

    def check_ts(self, flow, pkt):
        """
        检查流的时间戳，未超时返回True
        """
        return pkt.time - flow.start_ts < self.flow_max_duration

    def summary(self):
        print("=== Summary ===")
        # 流统计信息
        print("流总数：", self.flow_total_cnt),
        print("未结束的流总数：", self.current_flow_cnt)
        print("保存的流总数：", self.dumped_flow_cnt)
        # 数据包统计信息
        print("数据包总数：", self.processed_pkt_cnt)
        print("丢弃数据包总数：", self.droped_pkt_cnt)

    def dump_all(self):
        for hash in self.flows_dict.keys():
            print(self.flows_dict[hash].flow_id)
            self.dumped_flow_cnt += 1
            self.flows_dict[hash].dump(self.output_dir, self.dump)

    def run(self):
        pkts = rdpcap(self.source, count=self.count)
        for pkt in pkts:

            self.processed_pkt_cnt += 1

            # 过滤掉非IP协议栈的数据包
            if IP not in pkt:
                self.droped_pkt_cnt += 1
                continue

            try:
                hash = self.hash_pkt(pkt)
            except AttributeError:
                # 无法hash意味着没有二元组的信息
                self.droped_pkt_cnt += 1
                continue

            if hash not in self.flows_dict.keys():
                # 数据包hash未知，新建一个流
                self.create_new_flow(hash, pkt)
            else:
                # 数据包hash已知
                flow = self.flows_dict[hash]
                if not self.check_ts(flow, pkt):  # 检查数据包的时间戳是否符合条件
                    # 数据包已经超时
                    self.dump_flow(hash)
                    # 根据这个数据包新建一个流
                    self.create_new_flow(hash, pkt)
                elif not self.check_TCP_FIN(hash, pkt):
                    self.dump_flow(hash)
                else:
                    # 都符合，这个数据包就属于这个流
                    # pkt.show()
                    self.flows_dict[hash].add_pkt(pkt)

        # 所有数据包读取完毕，dump所有的流
        self.dump_all()
