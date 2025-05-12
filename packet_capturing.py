from scapy.all import sniff, IP, TCP, wrpcap
from collections import defaultdict
import threading
import queue
import time
import uuid
import statistics

class PacketCapture:
    def __init__(self, interface="eth0", output_file="captured.pcap"):
        self.interface = interface
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.output_file = output_file
        self.captured_packets = []

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)
            self.captured_packets.append(packet)

    def start_capture(self, capture_duration=30):
        def capture_thread():
            print(f"[+] Starting packet capture on interface: {self.interface}")
            while not self.stop_capture.is_set():
                sniff(iface=self.interface,
                      prn=self.packet_callback,
                      store=0,
                      timeout=5)

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()
        time.sleep(capture_duration)
        self.stop()

    def stop(self):
        print("[+] Stopping packet capture...")
        self.stop_capture.set()
        self.capture_thread.join()
        if self.captured_packets:
            wrpcap(self.output_file, self.captured_packets)
            print(f"[+] Saved {len(self.captured_packets)} packets to {self.output_file}")
        else:
            print("[!] No packets captured.")


class TrafficAnalyzer:
    def __init__(self):
        self.flow_data = {}

    def analyze_packet(self, packet):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        port_src = packet[TCP].sport
        port_dst = packet[TCP].dport
        ts = packet.time
        payload_len = len(packet[TCP].payload)
        flags = packet[TCP].flags

        # Determine flow key and direction
        key = (ip_src, ip_dst, port_src, port_dst)
        rev = (ip_dst, ip_src, port_dst, port_src)
        direction = 'fwd'
        if rev in self.flow_data:
            key = rev
            direction = 'bwd'

        # Initialize flow record if new
        F = self.flow_data.setdefault(key, {
            'uid': str(uuid.uuid4()),
            'originh': key[0], 'originp': key[2],
            'responh': key[1], 'responp': key[3],
            'start_time': ts, 'end_time': ts,
            'fwd_pkts_tot':0,'bwd_pkts_tot':0,
            'fwd_data_pkts_tot':0,'bwd_data_pkts_tot':0,
            'fwd_header_sizes':[],'bwd_header_sizes':[],
            # flag counters
            'flow_FIN_flag_count':0,'flow_SYN_flag_count':0,'flow_RST_flag_count':0,
            'flow_ACK_flag_count':0,'flow_CWR_flag_count':0,'flow_ECE_flag_count':0,
            'fwd_PSH_flag_count':0,'bwd_PSH_flag_count':0,
            'fwd_URG_flag_count':0,'bwd_URG_flag_count':0,
            # payload lists
            'fwd_payloads':[],'bwd_payloads':[],
            # inter-arrival times
            'fwd_iats':[],'bwd_iats':[],'last_fwd_ts':None,'last_bwd_ts':None,
            # subflow features
            'fwd_subflow':0,'bwd_subflow':0,
            'fwd_subflow_packets':0,'bwd_subflow_packets':0,
            'fwd_subflow_bytes':0,'bwd_subflow_bytes':0,
            'fwd_subflow_init_win':None,'bwd_subflow_init_win':None,
            # label placeholder
            'label':None
        })

        # update timestamps
        F['end_time'] = ts

        # header size
        hdr_sz = packet[TCP].dataofs * 4
        if direction == 'fwd':
            F['fwd_pkts_tot'] += 1
            if payload_len>0: F['fwd_data_pkts_tot'] += 1
            F['fwd_header_sizes'].append(hdr_sz)
            F['fwd_payloads'].append(payload_len)
            # IAT
            if F['last_fwd_ts'] is not None:
                F['fwd_iats'].append(ts - F['last_fwd_ts'])
            F['last_fwd_ts'] = ts
        else:
            F['bwd_pkts_tot'] += 1
            if payload_len>0: F['bwd_data_pkts_tot'] += 1
            F['bwd_header_sizes'].append(hdr_sz)
            F['bwd_payloads'].append(payload_len)
            if F['last_bwd_ts'] is not None:
                F['bwd_iats'].append(ts - F['last_bwd_ts'])
            F['last_bwd_ts'] = ts

        # flag counting
        if flags & 0x01:  F['flow_FIN_flag_count'] += 1
        if flags & 0x02:
            F['flow_SYN_flag_count'] += 1
            # subflow count on SYN
            if direction=='fwd':
                F['fwd_subflow'] += 1
                F['fwd_subflow_init_win'] = packet[TCP].window
            else:
                F['bwd_subflow'] += 1
                F['bwd_subflow_init_win'] = packet[TCP].window
        if flags & 0x04:  F['flow_RST_flag_count'] += 1
        if flags & 0x10:  F['flow_ACK_flag_count'] += 1
        if flags & 0x80:  F['flow_CWR_flag_count'] += 1
        if flags & 0x40:  F['flow_ECE_flag_count'] += 1
        if flags & 0x08:
            if direction=='fwd': F['fwd_PSH_flag_count']+=1
            else:                F['bwd_PSH_flag_count']+=1
        if flags & 0x20:
            if direction=='fwd': F['fwd_URG_flag_count']+=1
            else:                F['bwd_URG_flag_count']+=1

        return self._compute_features(F)

    def _compute_stats(self, values):
        if not values:
            return {'min':0,'max':0,'tot':0,'avg':0,'std':0}
        return {'min':min(values),'max':max(values),'tot':sum(values),
                'avg':sum(values)/len(values),'std':statistics.pstdev(values)}

    def _compute_features(self, F):
        duration = max(F['end_time'] - F['start_time'], 1e-6)
        total_pkts = F['fwd_pkts_tot'] + F['bwd_pkts_tot']
        total_payload = sum(F['fwd_payloads']) + sum(F['bwd_payloads'])

        fwd_pl = self._compute_stats(F['fwd_payloads'])
        bwd_pl = self._compute_stats(F['bwd_payloads'])
        all_pl = self._compute_stats(F['fwd_payloads']+F['bwd_payloads'])
        fwd_iat = self._compute_stats(F['fwd_iats'])
        bwd_iat = self._compute_stats(F['bwd_iats'])
        all_iat = self._compute_stats(F['fwd_iats']+F['bwd_iats'])

        features = {
            'uid':F['uid'], 'originh':F['originh'], 'originp':F['originp'],
            'responh':F['responh'], 'responp':F['responp'],
            'flow_duration':duration,
            'fwd_pkts_tot':F['fwd_pkts_tot'], 'bwd_pkts_tot':F['bwd_pkts_tot'],
            'fwd_data_pkts_tot':F['fwd_data_pkts_tot'],'bwd_data_pkts_tot':F['bwd_data_pkts_tot'],
            'fwd_pkts_per_sec':F['fwd_pkts_tot']/duration,'bwd_pkts_per_sec':F['bwd_pkts_tot']/duration,
            'flow_pkts_per_sec':total_pkts/duration,
            'down_up_ratio':(F['bwd_pkts_tot']/F['fwd_pkts_tot']) if F['fwd_pkts_tot'] else 0,
            'fwd_header_size_tot':sum(F['fwd_header_sizes']),'fwd_header_size_min':min(F['fwd_header_sizes'],default=0),
            'fwd_header_size_max':max(F['fwd_header_sizes'],default=0),'bwd_header_size_tot':sum(F['bwd_header_sizes']),
            'bwd_header_size_min':min(F['bwd_header_sizes'],default=0),'bwd_header_size_max':max(F['bwd_header_sizes'],default=0),
            'flow_FIN_flag_count':F['flow_FIN_flag_count'],'flow_SYN_flag_count':F['flow_SYN_flag_count'],
            'flow_RST_flag_count':F['flow_RST_flag_count'],'flow_ACK_flag_count':F['flow_ACK_flag_count'],
            'flow_CWR_flag_count':F['flow_CWR_flag_count'],'flow_ECE_flag_count':F['flow_ECE_flag_count'],
            'fwd_PSH_flag_count':F['fwd_PSH_flag_count'],'bwd_PSH_flag_count':F['bwd_PSH_flag_count'],
            'fwd_URG_flag_count':F['fwd_URG_flag_count'],'bwd_URG_flag_count':F['bwd_URG_flag_count'],
            # payload stats
            'fwd_pkts_payload.min':fwd_pl['min'],'fwd_pkts_payload.max':fwd_pl['max'],'fwd_pkts_payload.tot':fwd_pl['tot'],
            'fwd_pkts_payload.avg':fwd_pl['avg'],'fwd_pkts_payload.std':fwd_pl['std'],
            'bwd_pkts_payload.min':bwd_pl['min'],'bwd_pkts_payload.max':bwd_pl['max'],'bwd_pkts_payload.tot':bwd_pl['tot'],
            'bwd_pkts_payload.avg':bwd_pl['avg'],'bwd_pkts_payload.std':bwd_pl['std'],
            'flow_pkts_payload.min':all_pl['min'],'flow_pkts_payload.max':all_pl['max'],'flow_pkts_payload.tot':all_pl['tot'],
            'flow_pkts_payload.avg':all_pl['avg'],'flow_pkts_payload.std':all_pl['std'],
            # IAT stats
            'fwd_iat.min':fwd_iat['min'],'fwd_iat.max':fwd_iat['max'],'fwd_iat.tot':fwd_iat['tot'],
            'fwd_iat.avg':fwd_iat['avg'],'fwd_iat.std':fwd_iat['std'],
            'bwd_iat.min':bwd_iat['min'],'bwd_iat.max':bwd_iat['max'],'bwd_iat.tot':bwd_iat['tot'],
            'bwd_iat.avg':bwd_iat['avg'],'bwd_iat.std':bwd_iat['std'],
            'flow_iat.min':all_iat['min'],'flow_iat.max':all_iat['max'],'flow_iat.tot':all_iat['tot'],
            'flow_iat.avg':all_iat['avg'],'flow_iat.std':all_iat['std'],
            # rate and subflow
            'payload_bytes_per_second': total_payload/duration,
            'fwd_subflow':F['fwd_subflow'],'bwd_subflow':F['bwd_subflow'],
            'fwd_subflow_packets':F['fwd_subflow'],'fwd_subflow_bytes':F['fwd_data_pkts_tot'],
            'fwd_subflow_avg_bytes_per_packet':(F['fwd_data_pkts_tot']/F['fwd_pkts_tot']) if F['fwd_pkts_tot'] else 0,
            'fwd_subflow_init_win_bytes_forward':F['fwd_subflow_init_win'],
            'bwd_subflow_packets':F['bwd_subflow'],'bwd_subflow_bytes':F['bwd_data_pkts_tot'],
            'bwd_subflow_avg_bytes_per_packet':(F['bwd_data_pkts_tot']/F['bwd_pkts_tot']) if F['bwd_pkts_tot'] else 0,
            'bwd_subflow_init_win_bytes_forward':F['bwd_subflow_init_win'],
            'label':F['label']
        }
        return features


if __name__ == "__main__":
    INTERFACE = "eth0"   # replace with your VM interface
    CAPTURE_TIME = 30
    PCAP_FILE = "captured.pcap"

    capture = PacketCapture(interface=INTERFACE, output_file=PCAP_FILE)
    capture.start_capture(capture_duration=CAPTURE_TIME)

    analyzer = TrafficAnalyzer()
    seen = set()
    while not capture.packet_queue.empty():
        pkt = capture.packet_queue.get()
        feat = analyzer.analyze_packet(pkt)
        if feat['uid'] not in seen:
            print(feat)
            seen.add(feat['uid'])
    print("[+] Done.")
