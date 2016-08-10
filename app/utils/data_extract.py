#coding:UTF-8
__author__ = 'dj'

from scapy.all import *
from collections import OrderedDict
import re
import binascii
import base64

#Web连接数据HTTP 80,8080
def web_data(PCAPS, host_ip):
    ip_port_id_list = list()
    id = 0
    for pcap in PCAPS:
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            src = pcap.getlayer(IP).src
            dst = pcap.getlayer(IP).dst
            sport = pcap.sport
            dport = pcap.dport
            if sport == 80 or sport == 8080:
                port = dport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'HTTP', 'id':id})
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'HTTP', 'id':id})
                else:
                    pass
            elif dport == 80 or dport == 8080:
                port = sport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'HTTP', 'id':id})
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'HTTP', 'id':id})
                else:
                    pass
            else:
                pass
        id += 1
    ip_port_ids_dict = OrderedDict()    #{'192.134.13.234:232':[2,3,4,5],'192.134.13.234:236':[4,3,2,4,3]}
    for ip_port_id in ip_port_id_list:
        if ip_port_id['ip_port'] in ip_port_ids_dict:
            ip_port_ids_dict[ip_port_id['ip_port']].append(ip_port_id['id'])#PCAPS[ip_port_id['id']].load)
        else:
            ip_port_ids_dict[ip_port_id['ip_port']] = [ip_port_id['id']] #[PCAPS[ip_port_id['id']].load]
    ip_port_data_list = list()
    data_id = 0
    for ip_port, load_list in ip_port_ids_dict.items():
        data_id += 1
        ip_port_data_list.append({'data_id':data_id,'ip_port':ip_port, 'data':''.join([PCAPS[i].load for i in load_list]), 'lens':'%.3f'%(sum([len(corrupt_bytes(PCAPS[i])) for i in load_list])/1024.0)})
    return ip_port_data_list

#Mail连接数据POP3 110, IMAP 143,SMTP 25
def mail_data(PCAPS, host_ip):
    ip_port_id_list = list()
    id = 0
    for pcap in PCAPS:
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            src = pcap.getlayer(IP).src
            dst = pcap.getlayer(IP).dst
            sport = pcap.sport
            dport = pcap.dport
            if sport == 110:
                port = dport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'POP3', 'id':id})
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'POP3', 'id':id})
                else:
                    pass
            elif sport == 143:
                port = dport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'IMAP', 'id':id})
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'IMAP', 'id':id})
                else:
                    pass
            elif sport == 25:
                port = dport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'SMTP', 'id':id})
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'SMTP', 'id':id})
                else:
                    pass
            elif dport == 110:
                port = sport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'POP3', 'id':id})
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'POP3', 'id':id})
                else:
                    pass
            elif dport == 143:
                port = sport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'IMAP', 'id':id})
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'IMAP', 'id':id})
                else:
                    pass
            elif dport == 25:
                port = sport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'SMTP', 'id':id})
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + 'SMTP', 'id':id})
                else:
                    pass
            else:
                pass
        id += 1
    ip_port_ids_dict = OrderedDict()    #{'192.134.13.234:232':[2,3,4,5],'192.134.13.234:232':[4,3,2,4,3]}
    for ip_port_id in ip_port_id_list:
        if ip_port_id['ip_port'] in ip_port_ids_dict:
            ip_port_ids_dict[ip_port_id['ip_port']].append(ip_port_id['id'])#PCAPS[ip_port_id['id']].load)
        else:
            ip_port_ids_dict[ip_port_id['ip_port']] = [ip_port_id['id']] #[PCAPS[ip_port_id['id']].load]
    ip_port_data_list = list()
    data_id = 0
    for ip_port, load_list in ip_port_ids_dict.items():
        data_id += 1
        ip_port_data_list.append({'data_id':data_id,'ip_port':ip_port, 'data':''.join([PCAPS[i].load for i in load_list]), 'lens':'%.3f'%(sum([len(corrupt_bytes(PCAPS[i])) for i in load_list])/1024.0)})
    return ip_port_data_list


#Telnet连接数据,telnet 23,FTP控制数据 ftp 21
def telnet_ftp_data(PCAPS, host_ip, tfport):
    if tfport == 21:
        proto = 'FTP'
    elif tfport == 23:
        proto = 'Telnet'
    else:
        proto = 'Other'
    ip_port_id_list = list()
    id = 0
    for pcap in PCAPS:
        if pcap.haslayer(TCP) and pcap.haslayer(Raw):
            src = pcap.getlayer(IP).src
            dst = pcap.getlayer(IP).dst
            sport = pcap.sport
            dport = pcap.dport
            if sport == tfport:
                port = dport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + proto, 'id':id})
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + proto, 'id':id})
                else:
                    pass
            elif dport == tfport:
                port = sport
                if src == host_ip:
                    ip = dst
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + proto, 'id':id})
                elif dst == host_ip:
                    ip = src
                    ip_port_id_list.append({'ip_port':ip+ ':' + str(port) + ':' + proto, 'id':id})
                else:
                    pass
            else:
                pass
        id += 1
    ip_port_ids_dict = OrderedDict()    #{'192.134.13.234:232':[2,3,4,5],'192.134.13.234:232':[4,3,2,4,3]}
    for ip_port_id in ip_port_id_list:
        if ip_port_id['ip_port'] in ip_port_ids_dict:
            ip_port_ids_dict[ip_port_id['ip_port']].append(ip_port_id['id'])#PCAPS[ip_port_id['id']].load)
        else:
            ip_port_ids_dict[ip_port_id['ip_port']] = [ip_port_id['id']] #[PCAPS[ip_port_id['id']].load]
    ip_port_data_list = list()
    data_id = 0
    for ip_port, load_list in ip_port_ids_dict.items():
        data_id += 1
        ip_port_data_list.append({'data_id':data_id,'ip_port':ip_port, 'data':''.join([PCAPS[i].load for i in load_list]), 'lens':'%.3f'%(sum([len(corrupt_bytes(PCAPS[i])) for i in load_list])/1024.0)})
    return ip_port_data_list


#FTP:login: tteesstt\r\x00\r\nPassword: capture\r
#敏感数据
def sen_data(PCAPS, host_ip):
    sendata_list = list()
    webdata = web_data(PCAPS, host_ip)
    maildata = mail_data(PCAPS, host_ip)
    telnetdata = telnet_ftp_data(PCAPS, host_ip, 23)
    ftpdata = telnet_ftp_data(PCAPS, host_ip, 21)

    #Telnet协议帐号密码
    telnet_pattern1 = re.compile(r'6c6f67696e3a.*?0d|4c6f67696e3a.*?0d') #login:
    telnet_pattern2 = re.compile(r'50617373776f72643a.*?0d|70617373776f72643a.*?0d') #Password:
    for telnet in telnetdata:
        data = binascii.hexlify(telnet['data'])
        login = telnet_pattern1.findall(data)
        password = telnet_pattern2.findall(data)
        restu = ''
        restp = ''
        if login:
            restu = str(list(set([binascii.unhexlify(i).strip() for i in login])))
        if password:
            restp = str(list(set([binascii.unhexlify(i).strip() for i in password])))
            result = restu + '     ' + restp
        if restp.strip():
            sendata_list.append({'ip_port': telnet['ip_port'], 'result': result, 'data':telnet['data']})

    #FTP协议帐号密码
    ftp_patternl = re.compile(r'USER(.*?)331', re.S)
    ftp_patternp = re.compile(r'PASS(.*?)230', re.S)
    for ftp in ftpdata:
        data = ftp['data']
        user = ftp_patternl.search(data)
        passwd = ftp_patternp.search(data)
        restu = ''
        restp = ''
        if user:
            restu = 'USER ' + user.group(1)
        if passwd:
            restp = 'PASS' + passwd.group(1)
            result = restu + '     ' + restp
        if restp.strip():
            sendata_list.append({'ip_port': ftp['ip_port'], 'result': result, 'data':data})

    #Mail协议帐号密码
    mail_patternu = re.compile(r'dXNlcm5hbWU6(.*?)334', re.S)
    mail_patternp = re.compile(r'UGFzc3dvcmQ6(.*?)235', re.S)
    for mail in maildata:
        data = mail['data']
        username = mail_patternu.search(data)
        password = mail_patternp.search(data)
        restu = ''
        restp = ''
        if username:
            restu = 'username : ' + base64.b64decode(username.group(1).strip())
        if password:
            restp = 'password : ' + base64.b64decode(password.group(1).strip())
            result = restu + '     ' + restp
        if restp.strip():
            sendata_list.append({'ip_port': mail['ip_port'], 'result': result, 'data':data})

    #HTTP协议帐号密码
    web_patternu = re.compile(r'((txtUid|username|user|name)=(.*?))&', re.I)
    web_patternp = re.compile(r'((txtPwd|password|pwd|passwd)=(.*?))&', re.I)
    tomcat_pattern = re.compile(r'Authorization: Basic(.*)')
    for web in webdata:
        data = web['data']
        username = web_patternu.findall(data)
        password = web_patternp.findall(data)
        tomcat = tomcat_pattern.findall(data)
        restu = ''
        restp = ''
        if username:
            restu = str(list(set([i for i,j,k in username])))
        if password:
            restp = str(list(set([i for i,j,k in password])))
            result = restu + '     ' + restp
        if tomcat:
            result = list(set([base64.b64decode(t.strip().replace('%3d', '=')) for t in tomcat]))
        if restp.strip():
            sendata_list.append({'ip_port': web['ip_port'], 'result': result, 'data':data})
    return sendata_list