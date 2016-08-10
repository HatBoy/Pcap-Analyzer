#coding:UTF-8
__author__ = 'dj'

from scapy.all import *
import collections

#数据包大小统计
def pcap_len_statistic(PCAPS):
    pcap_len_dict = {'0-300':0, '301-600':0, '601-900':0, '901-1200':0, '1201-1500':0}
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if 0< pcap_len < 300:
            pcap_len_dict['0-300'] += 1
        elif 301 <= pcap_len < 600:
            pcap_len_dict['301-600'] += 1
        elif 601 <= pcap_len < 900:
            pcap_len_dict['601-900'] += 1
        elif 901 <= pcap_len < 1200:
            pcap_len_dict['901-1200'] += 1
        elif 1201 <= pcap_len <= 1500:
            pcap_len_dict['1201-1500'] += 1
        else:
            pass
    return pcap_len_dict

#常见协议统计IP,IPv6,TCP,UDP,ARP,ICMP,DNS,HTTP,HTTPS,Other
def common_proto_statistic(PCAPS):
    common_proto_dict = collections.OrderedDict()
    common_proto_dict['IP'] = 0
    common_proto_dict['IPv6'] = 0
    common_proto_dict['TCP'] = 0
    common_proto_dict['UDP'] = 0
    common_proto_dict['ARP'] = 0
    common_proto_dict['ICMP'] = 0
    common_proto_dict['DNS'] = 0
    common_proto_dict['HTTP'] = 0
    common_proto_dict['HTTPS'] = 0
    common_proto_dict['Others'] = 0
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            common_proto_dict['IP'] += 1
        elif pcap.haslayer(IPv6):
            common_proto_dict['IPv6'] += 1
        if pcap.haslayer(TCP):
            common_proto_dict['TCP'] += 1
        elif pcap.haslayer(UDP):
            common_proto_dict['UDP'] += 1
        if pcap.haslayer(ARP):
            common_proto_dict['ARP'] += 1
        elif pcap.haslayer(ICMP):
            common_proto_dict['ICMP'] += 1
        elif pcap.haslayer(DNS):
            common_proto_dict['DNS'] += 1
        elif pcap.haslayer(TCP):
            tcp = pcap.getlayer(TCP)
            dport = tcp.dport
            sport = tcp.sport
            if dport == 80 or sport == 80:
                common_proto_dict['HTTP'] += 1
            elif dport == 443 or sport == 443:
                common_proto_dict['HTTPS'] += 1
            else:
                common_proto_dict['Others'] += 1
        elif pcap.haslayer(UDP):
            udp = pcap.getlayer(UDP)
            dport = udp.dport
            sport = udp.sport
            if dport == 5353 or sport == 5353:
                common_proto_dict['DNS'] += 1
            else:
                common_proto_dict['Others'] += 1
        elif pcap.haslayer(ICMPv6ND_NS):
            common_proto_dict['ICMP'] += 1
        else:
            common_proto_dict['Others'] += 1
    return common_proto_dict

#最多协议数量统计
def most_proto_statistic(PCAPS, PD):
    protos_list = list()
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        protos_list.append(data['Procotol'])
    most_count_dict = collections.OrderedDict(collections.Counter(protos_list).most_common(10))
    return most_count_dict

#http/https协议统计
def http_statistic(PCAPS):
    http_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer(TCP):
            tcp = pcap.getlayer(TCP)
            dport = tcp.dport
            sport = tcp.sport
            ip = None
            if dport == 80 or dport == 443:
                ip = pcap.getlayer(IP).dst
            elif sport == 80 or sport == 443:
                ip = pcap.getlayer(IP).src
            if ip:
                if ip in http_dict:
                    http_dict[ip] += 1
                else:
                    http_dict[ip] = 1
    return http_dict

#DNS协议统计
def dns_statistic(PCAPS):
    dns_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer(DNSQR):
            qname = pcap.getlayer(DNSQR).qname
            if qname in dns_dict:
                dns_dict[qname] += 1
            else:
                dns_dict[qname] = 1
    return dns_dict