#coding:UTF-8
__author__ = 'dj'

from scapy.all import *
import time
import re
import collections
import binascii
from .data_extract import web_data, telnet_ftp_data

#根据可疑端口判断是否有木马病毒
def port_warning(PCAPS, host_ip):
    with open('./app/utils/protocol/WARN', 'r', encoding='UTF-8') as f:
        warns = f.readlines()
    WARN_DICT = dict()
    for warn in warns:
        warn = warn.strip()
        WARN_DICT[int(warn.split(':')[0])] = warn.split(':')[1]
    #迭代数据包
    portwarn_list = list()
    for pcap in PCAPS:
        if pcap.haslayer(TCP):
            tcp = pcap.getlayer(TCP)
            src = pcap.getlayer(IP).src
            dst = pcap.getlayer(IP).dst
            sport = tcp.sport
            dport = tcp.dport
            if src == host_ip:
                ip = dst
                if sport in WARN_DICT:
                    portwarn_list.append({'ip_port':ip+':'+str(sport), 'warn': WARN_DICT[sport],'time':time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pcap.time)), 'data':pcap.summary()})
                elif dport in WARN_DICT:
                    portwarn_list.append({'ip_port':ip+':'+str(dport), 'warn':WARN_DICT[dport],'time':time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pcap.time)), 'data':pcap.summary()})
                else:
                    pass
            elif dst == host_ip:
                ip = src
                if sport in WARN_DICT:
                    portwarn_list.append({'ip_port':ip+':'+str(sport), 'warn': WARN_DICT[sport],'time':time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pcap.time)), 'data':pcap.summary()})
                elif dport in WARN_DICT:
                    portwarn_list.append({'ip_port':ip+':'+str(dport), 'warn':WARN_DICT[dport],'time':time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pcap.time)), 'data':pcap.summary()})
                else:
                    pass
            else:
                pass
    return portwarn_list


#根据WEB内容来匹配常见WEB攻击,SQL注入，XSS，暴力破解，目录遍历，任意文件下载，木马
def web_warning(PCAPS, host_ip):
    with open('./app/utils/warning/HTTP_ATTACK', 'r', encoding='UTF-8') as f:
        attacks = f.readlines()
    ATTACK_DICT = dict()
    for attack in attacks:
        attack = attack.strip()
        ATTACK_DICT[attack.split(' : ')[0]] = attack.split(' : ')[1]
    webdata = web_data(PCAPS, host_ip)
    webwarn_list = list()
    webbur_list = list()
    web_patternu = re.compile(r'((txtUid|username|user|name)=(.*?))&', re.I)
    web_patternp = re.compile(r'((txtPwd|password|pwd|passwd)=(.*?))&', re.I)
    tomcat_pattern = re.compile(r'Authorization: Basic(.*)')
    for web in webdata:
        data = web['data']
        #HTTP爆破
        username = web_patternu.findall(data)
        password = web_patternp.findall(data)
        tomcat = tomcat_pattern.findall(data)
        if username or password or tomcat:
            webbur_list.append(web['ip_port'].split(':')[0])
        for pattn, attk in ATTACK_DICT.items(): #特征码和攻击名称
            if pattn.upper() in data.upper():
                webwarn_list.append({'ip_port': web['ip_port'].split(':')[0]+':'+web['ip_port'].split(':')[1], 'warn':attk, 'time':pattn, 'data':data})
    ip_count = collections.Counter(webbur_list)
    warn_ip = {k:y for k,y in ip_count.items() if y>10}
    for ip, count in warn_ip.items():
        webwarn_list.append({'ip_port': ip, 'warn':u'HTTP暴力破解', 'time': str(count), 'data':None})
    return webwarn_list

#根据FTP登录失败次数，判断FTP暴力破解攻击,登录次数打大于10次算暴力破解
def ftp_warning(PCAPS, host_ip):
    ftpdata = telnet_ftp_data(PCAPS, host_ip, 21)
    ftpwarn_list = list()
    ftp503_list = list()
    for ftp in ftpdata:
        if '530 Not logged in' in ftp['data']:
            ftp503_list.append(ftp['ip_port'].split(':')[0])
    ip_count = collections.Counter(ftp503_list)
    warn_ip = {k:y for k,y in ip_count.items() if y>10}
    for ip, count in warn_ip.items():
        ftpwarn_list.append({'ip_port': ip, 'warn':u'FTP暴力破解', 'time': str(count), 'data':None})
    return ftpwarn_list

#未完，抓取数据替换正则表达式
#根据Telnet登录失败次数，判断FTP暴力破解攻击,登录次数打大于10次算暴力破解
def telnet_warning(PCAPS, host_ip):
    telnetdata = telnet_ftp_data(PCAPS, host_ip, 23)
    telnetwarn_list = list()
    telnetfail_list = list()
    for telnet in telnetdata:
        if '4c6f67696e204661696c6564' in binascii.hexlify(telnet['data']) or '6c6f67696e206661696c6564' in binascii.hexlify(telnet['data']):
            telnetfail_list.append(telnet['ip_port'].split(':')[0])
    ip_count = collections.Counter(telnetfail_list)
    warn_ip = {k:y for k,y in ip_count.items() if y>10}
    for ip, count in warn_ip.items():
        telnetwarn_list.append({'ip_port': ip, 'warn':u'Telnet暴力破解', 'time': str(count), 'data':None})
    return telnetwarn_list

#同理得到ARP攻击警告
def arp_warning(PCAPS):
    arpwarn_list = list()
    arp_list = list()
    for pcap in PCAPS:
        if pcap.haslayer(ARP) and pcap.getlayer(ARP).op == 2:
            arp_list.append({'src': pcap.src, 'summary': pcap.summary()})
    arpsrc_dict = dict()
    for arp in arp_list:
        if arp['src'] in arpsrc_dict:
            arpsrc_dict[arp['src']].append(arp['summary'])
        else:
            arpsrc_dict[arp['src']] = [arp['summary']]
    for src, summary in arpsrc_dict.items():
        if len(set(summary)) == 1:
            pass
        else:
            arpwarn_list.append({'ip_port': src, 'warn': u'ARP欺骗', 'time': set([s.split()[-1] for s in summary]), 'data':None})
    return arpwarn_list


def exception_warning(PCAPS, host_ip):
    warn_list = list()
    port_list = port_warning(PCAPS, host_ip)
    arp_list = arp_warning(PCAPS)
    web_list = web_warning(PCAPS, host_ip)
    telnet_list = telnet_warning(PCAPS, host_ip)
    ftp_list = ftp_warning(PCAPS, host_ip)
    if web_list:
        warn_list.extend(web_list)
    if telnet_list:
        warn_list.extend(telnet_list)
    if ftp_list:
        warn_list.extend(ftp_list)
    if port_list:
        warn_list.append(port_list)
    if arp_list:
        warn_list.append(arp_list)
    return warn_list