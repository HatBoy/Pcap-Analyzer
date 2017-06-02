#coding:UTF-8
__author__ = 'dj'

from scapy.all import *
from collections import OrderedDict
import re
import time
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
        raw_data = b''.join([PCAPS[i].load for i in load_list])
        #解决编码问题
        tmp_data = raw_data.decode('UTF-8', 'ignore')
        if ('gbk' in tmp_data) or ('GBK' in tmp_data):
            data = raw_data.decode('GBK', 'ignore')
        else:
            data = tmp_data
        ip_port_data_list.append({'data_id':data_id,'ip_port':ip_port, 'data':data, 'raw_data':raw_data, 'lens':'%.3f'%(sum([len(corrupt_bytes(PCAPS[i])) for i in load_list])/1024.0)})
    return ip_port_data_list

#Mail连接数据POP3 src 110, IMAP src 143,SMTP des 25
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
        raw_data = b''.join([PCAPS[i].load for i in load_list])
        if 'SMTP' in ip_port:
            parse_data = smtp_parse(raw_data)
        elif 'POP3' in ip_port:
            parse_data = pop3_parse(raw_data)
        elif 'IMAP' in ip_port:
            parse_data = imap_parse(raw_data)
        else:
            parse_data = None
        #解决编码问题
        data = raw_data.decode('UTF-8', 'ignore')
        ip_port_data_list.append({'data_id':data_id,'ip_port':ip_port, 'data':data, 'raw_data':raw_data, 'parse_data':parse_data,'lens':'%.3f'%(sum([len(corrupt_bytes(PCAPS[i])) for i in load_list])/1024.0)})
    return ip_port_data_list

#解析SMTP协议
def smtp_parse(raw_data):
    data = raw_data.decode('UTF-8', 'ignore')
    #各种字段正则表达式
    mailuser_p = re.compile(r'dXNlcm5hbWU6\r\n(.*?)\r\n', re.S)
    mailpasswd_p = re.compile(r'UGFzc3dvcmQ6\r\n(.*?)\r\n', re.S)
    maildate_p = re.compile(r'Date:(.*?)\r\n', re.S)
    mailfrom_p = re.compile(r'RCPT TO:(.*?)\r\n', re.S)
    mailto_p = re.compile(r'To:(.*?)\r\n', re.S)
    mailcc_p = re.compile(r'Cc:(.*?)\r\nSubject', re.S)
    mailsubject_p = re.compile(r'Subject:(.*?)\r\n', re.S)
    mailmessageid_p = re.compile(r'Message-ID:(.*?)\r\n', re.S)
    charset_p = re.compile(r'charset="(.*?)"', re.S)
    mailcontent_p = re.compile(r'Content-Transfer-Encoding: base64\r\n\r\n(.*?)\r\n\r\n------=', re.S)

    username_ = mailuser_p.search(data)
    password_ = mailpasswd_p.search(data)
    maildate_ = maildate_p.search(data)
    mailfrom_ = mailfrom_p.search(data)
    mailto_ = mailto_p.search(data)
    mailcc_ = mailcc_p.search(data)
    mailsubject_ = mailsubject_p.search(data)
    mailmessageid_ = mailmessageid_p.search(data)
    charset_ = charset_p.search(data)
    mailcontent_ = mailcontent_p.search(data)
    charset = charset_.group(1) if charset_ else 'UTF-8'
    username = base64.b64decode(base64padding(username_.group(1))).decode('UTF-8') if username_ else None
    password = base64.b64decode(base64padding(password_.group(1))).decode('UTF-8') if password_ else None
    maildate = maildate_.group(1).strip() if maildate_ else None
    mailfrom = mailfrom_.group(1).strip() if mailfrom_ else None
    mailto = mailto_.group(1).strip() if mailto_ else None
    mailcc = mailcc_.group(1).strip() if mailcc_ else None
    mailmessageid = mailmessageid_.group(1).strip() if mailmessageid_ else None
    if mailsubject_:
        mailsubject_ = mailsubject_.group(1).strip()
        if mailsubject_ and '=?' in mailsubject_:
            mailsubject_ = mailsubject_.split('?')
            mailsubject = base64.b64decode(base64padding(mailsubject_[3])).decode(mailsubject_[1], 'ignore')
        else:
            mailsubject = mailsubject_
    else:
        mailsubject = None
    if mailcontent_:
        mailcontent_ = mailcontent_.group(1).strip().replace('\r\n', '')
        mailcontent = base64.b64decode(base64padding(mailcontent_)).decode(charset, 'ignore')
    else:
        mailcontent = None
    attachs_dict = findmail_attachs(raw_data)
    parse_data = {'username':username, 'password':password, 'maildate':maildate, 'mailfrom':mailfrom, 'mailto':mailto, 'mailcc':mailcc, 'mailsubject':mailsubject, 'mailmessageid':mailmessageid, 'mailcontent':mailcontent, 'attachs_dict':attachs_dict}
    return parse_data

#填充不符合规范的base64数据
def base64padding(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += '='* missing_padding
    return data

#寻找mail中的所有附件
def findmail_attachs(raw_data):
    filename_p = re.compile(r'filename="(.*?)"', re.S)
    attachs_dict = dict()
    charset = 'UTF-8'
    data_list = raw_data.decode('UTF-8', 'ignore').split('\r\n\r\n')
    switch = False
    for data in data_list:
        if switch:
            if data:
                data = data.strip().replace('\r\n', '')
                filedata = base64.b64decode(base64padding(data))
            else:
                filedata = None
            try:
                filedata = filedata.decode(charset)
            except Exception as e:
                pass
            attachs_dict[filename] = filedata
            switch = False
        if 'filename' in data:
            switch = True
            filename_ = filename_p.search(data)
            if filename_:
                filename_ = filename_.group(1).strip()
                if filename_ and '=?' in filename_:
                    filename_ = filename_.split('?')
                    charset = filename_[1]
                    filename = base64.b64decode(base64padding(filename_[3])).decode(charset, 'ignore')
                else:
                    filename = filename_
            else:
                filename = 'unknow'
    return attachs_dict

#解析POP3协议
def pop3_parse(raw_data):
    data = raw_data.decode('UTF-8', 'ignore')
    #各种字段正则表达式
    mailuser_p = re.compile(r'USER(.*?)\r\n', re.S)
    mailpasswd_p = re.compile(r'PASS(.*?)\r\n', re.S)
    maildate_p = re.compile(r'Date:(.*?)\r\n', re.S)
    mailfrom_p = re.compile(r'From:(.*?)\r\n', re.S)
    mailto_p = re.compile(r'To:(.*?)\r\n', re.S)
    mailcc_p = re.compile(r'Cc:(.*?)\r\nSubject', re.S)
    mailsubject_p = re.compile(r'Subject:(.*?)\r\n', re.S)
    mailmessageid_p = re.compile(r'Message-ID:(.*?)\r\n', re.S)
    charset_p = re.compile(r'charset="(.*?)"', re.S)
    mailcontent_p = re.compile(r'Content-Transfer-Encoding: base64\r\n\r\n(.*?)\r\n\r\n------=', re.S)

    username_ = mailuser_p.search(data)
    password_ = mailpasswd_p.search(data)
    maildate_ = maildate_p.findall(data)
    mailfrom_ = mailfrom_p.findall(data)
    mailto_ = mailto_p.findall(data)
    mailcc_ = mailcc_p.search(data)
    mailsubject_ = mailsubject_p.findall(data)
    mailmessageid_ = mailmessageid_p.search(data)
    charset_ = charset_p.search(data)
    mailcontent_ = mailcontent_p.search(data)
    charset = charset_.group(1) if charset_ else 'UTF-8'
    username = username_.group(1).strip() if username_ else None
    password = password_.group(1).strip() if password_ else None
    maildate = maildate_[-1].strip() if maildate_ else None
    mailfrom_ = mailfrom_[-1].strip() if mailfrom_ else None
    if mailfrom_ and '=?' in mailfrom_:
        mailfrom_ = mailfrom_.split('?')
        mailfrom_address = mailfrom_[-1].split()[-1]
        mailfrom_name = base64.b64decode(base64padding(mailfrom_[3])).decode(mailfrom_[1], 'ignore')
        mailfrom = "{}".format(mailfrom_name) + " " + mailfrom_address
    else:
        mailfrom = mailfrom_
    mailto_ = mailto_[-1].strip() if mailto_ else None
    if mailto_ and '=?' in mailto_:
        mailto_ = mailto_.split('?')
        mailto_address = mailto_[-1].split()[-1]
        mailto_name = base64.b64decode(base64padding(mailto_[3])).decode(mailto_[1], 'ignore')
        mailto = "{}".format(mailto_name) + " " + mailto_address
    else:
        mailto = mailto_
    mailcc = mailcc_.group(1).strip() if mailcc_ else None
    mailmessageid = mailmessageid_.group(1).strip() if mailmessageid_ else None
    if mailsubject_:
        mailsubject_ = mailsubject_[-1].strip()
        if mailsubject_ and '=?' in mailsubject_:
            mailsubject_ = mailsubject_.split('?')
            mailsubject = base64.b64decode(base64padding(mailsubject_[3])).decode(mailsubject_[1], 'ignore')
        else:
            mailsubject = mailsubject_
    else:
        mailsubject = None
    if mailcontent_:
        mailcontent_ = mailcontent_.group(1).strip().replace('\r\n', '')
        mailcontent = base64.b64decode(base64padding(mailcontent_)).decode(charset, 'ignore')
    else:
        mailcontent = None
    attachs_dict = findmail_attachs(raw_data)
    parse_data = {'username':username, 'password':password, 'maildate':maildate, 'mailfrom':mailfrom, 'mailto':mailto, 'mailcc':mailcc, 'mailsubject':mailsubject, 'mailmessageid':mailmessageid, 'mailcontent':mailcontent, 'attachs_dict':attachs_dict}
    return parse_data

#解析IMAP协议
def imap_parse(raw_data):
    data = raw_data.decode('UTF-8', 'ignore')
    #各种字段正则表达式
    mailuser_pwd_p = re.compile(r'LOGIN(.*?)\r\n', re.S)
    maildate_p = re.compile(r'Date:(.*?)\r\n', re.S)
    mailfrom_p = re.compile(r'From:(.*?)\r\n', re.S)
    mailto_p = re.compile(r'To:(.*?)\r\n', re.S)
    mailcc_p = re.compile(r'Cc:(.*?)\r\nSubject', re.S)
    mailsubject_p = re.compile(r'Subject:(.*?)\r\n', re.S)
    mailmessageid_p = re.compile(r'Message-ID:(.*?)\r\n', re.S)
    charset_p = re.compile(r'charset="(.*?)"', re.S)
    mailcontent_p = re.compile(r'Content-Transfer-Encoding: base64\r\n\r\n(.*?)\r\n\r\n------=', re.S)

    username_pwd_ = mailuser_pwd_p.search(data)
    maildate_ = maildate_p.findall(data)
    mailfrom_ = mailfrom_p.findall(data)
    mailto_ = mailto_p.findall(data)
    mailcc_ = mailcc_p.search(data)
    mailsubject_ = mailsubject_p.findall(data)
    mailmessageid_ = mailmessageid_p.search(data)
    charset_ = charset_p.search(data)
    mailcontent_ = mailcontent_p.search(data)
    charset = charset_.group(1) if charset_ else 'UTF-8'
    username_pwd = username_pwd_.group(1).strip() if username_pwd_ else None
    if username_pwd:
        username = username_pwd.split()[0]
        password = username_pwd.split()[-1][1:-1]
    else:
        username =None
        password = None
    maildate = maildate_[-1].strip() if maildate_ else None
    mailfrom_ = mailfrom_[-1].strip() if mailfrom_ else None
    if mailfrom_ and ('=?' in mailfrom_):
        mailfrom_ = mailfrom_.split('?')
        mailfrom_address = mailfrom_[-1].split()[-1]
        mailfrom_name = base64.b64decode(base64padding(mailfrom_[3])).decode(mailfrom_[1], 'ignore')
        mailfrom = "{}".format(mailfrom_name) + " " + mailfrom_address
    else:
        mailfrom = mailfrom_
    mailto_ = mailto_[-1].strip() if mailto_ else None
    if mailto_ and '=?' in mailto_:
        mailto_ = mailto_.split('?')
        mailto_address = mailto_[-1].split()[-1]
        mailto_name = base64.b64decode(base64padding(mailto_[3])).decode(mailto_[1], 'ignore')
        mailto = "{}".format(mailto_name) + " " + mailto_address
    else:
        mailto = mailto_
    mailcc = mailcc_.group(1).strip() if mailcc_ else None
    mailmessageid = mailmessageid_.group(1).strip() if mailmessageid_ else None
    if mailsubject_:
        mailsubject_ = mailsubject_[-1].strip()
        if mailsubject_ and '=?' in mailsubject_:
            mailsubject_ = mailsubject_.split('?')
            mailsubject = base64.b64decode(base64padding(mailsubject_[3])).decode(mailsubject_[1], 'ignore')
        else:
            mailsubject = mailsubject_
    else:
        mailsubject = None
    if mailcontent_:
        mailcontent_ = mailcontent_.group(1).strip().replace('\r\n', '')
        mailcontent = base64.b64decode(base64padding(mailcontent_)).decode(charset, 'ignore')
    else:
        mailcontent = None
    attachs_dict = findmail_attachs(raw_data)
    parse_data = {'username':username, 'password':password, 'maildate':maildate, 'mailfrom':mailfrom, 'mailto':mailto, 'mailcc':mailcc, 'mailsubject':mailsubject, 'mailmessageid':mailmessageid, 'mailcontent':mailcontent, 'attachs_dict':attachs_dict}
    return parse_data


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
        raw_data = b''.join([PCAPS[i].load for i in load_list])
        #解决编码问题
        data = raw_data.decode('UTF-8', 'ignore')
        ip_port_data_list.append({'data_id':data_id,'ip_port':ip_port, 'data':data, 'raw_data':raw_data, 'lens':'%.3f'%(sum([len(corrupt_bytes(PCAPS[i])) for i in load_list])/1024.0)})
    return ip_port_data_list

#客户端信息
def client_info(PCAPS):
    with open('./app/utils/warning/CLIENT_INFO', 'r', encoding='UTF-8') as f:
        lines = f.readlines()
    client_patterns = [i.strip() for i in lines]
    clientinfo_list = list()
    allpayloads_dict = OrderedDict()
    sessions = PCAPS.sessions()
    for sess, ps in sessions.items():
        payload = b''
        for p in ps:
            if p.haslayer(Raw):
                payload += p[Raw].load
            if payload:
                allpayloads_dict[sess] = payload.decode('UTF-8', 'ignore')
    for sess, payload in allpayloads_dict.items():
        pcap = sessions[sess][0]
        times = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pcap.time))
        if pcap.haslayer(Ether):
            ether = pcap.getlayer(Ether)
            ether_dst = ether.dst
            ether_src = ether.src
            if pcap.haslayer(IP):
                ip = pcap.getlayer(IP)
                ip_src = ip.src
                ip_dst = ip.dst
            else:
                ip_src = 'unknow'
                ip_dst = 'unknow'
        else:
            ether_dst = None
            ether_src = None
        clients_str = ''
        for pattern in client_patterns:
            pp = re.compile(pattern, re.S)
            client = pp.findall(payload)
            if client:
                clients_str = client[0] + ';' + clients_str
        if ether_dst and ether_src and clients_str:
            clientinfo_list.append({'sess':sess, 'ether_dst':ether_dst, 'ether_src':ether_src, 'ip_src':ip_src, 'ip_dst':ip_dst, 'clients':clients_str[:-1], 'time':times})
    return clientinfo_list


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
    for mail in maildata:
        data = mail['data']
        ip_port = mail['ip_port']
        if 'SMTP' in ip_port:
            mailuser_p = re.compile(r'dXNlcm5hbWU6\r\n(.*?)\r\n', re.S)
            mailpasswd_p = re.compile(r'UGFzc3dvcmQ6\r\n(.*?)\r\n', re.S)
            username_ = mailuser_p.search(data)
            password_ = mailpasswd_p.search(data)
            username = base64.b64decode(base64padding(username_.group(1))).decode('UTF-8') if username_ else None
            password = base64.b64decode(base64padding(password_.group(1))).decode('UTF-8') if password_ else None
        elif 'POP3' in ip_port:
            mailuser_p = re.compile(r'USER(.*?)\r\n', re.S)
            mailpasswd_p = re.compile(r'PASS(.*?)\r\n', re.S)
            username_ = mailuser_p.search(data)
            password_ = mailpasswd_p.search(data)
            username = username_.group(1).strip() if username_ else None
            password = password_.group(1).strip() if password_ else None
        elif 'IMAP' in ip_port:
            mailuser_pwd_p = re.compile(r'LOGIN(.*?)\r\n', re.S)
            username_pwd_ = mailuser_pwd_p.search(data)
            username_pwd = username_pwd_.group(1).strip() if username_pwd_ else None
            if username_pwd:
                username = username_pwd.split()[0]
                password = username_pwd.split()[-1][1:-1]
            else:
                username =None
                password = None
        else:
            username = None
            password = None
        result = ''
        if username:
            restu = 'username : ' + username
        if password:
            restp = 'password : ' + password
            result = restu + '     ' + restp
        if result.strip():
            sendata_list.append({'ip_port': mail['ip_port'], 'result': result, 'data':data})

    #HTTP协议帐号密码
    with open('./app/utils/warning/HTTP_DATA', 'r', encoding='UTF-8') as f:
        lines = f.readlines()
    user = lines[0].strip()
    passwd = lines[1].strip()
    web_patternu = re.compile('(({user})=(.*?))&'.format(user=user), re.I)
    web_patternp = re.compile('(({passwd})=(.*?))&'.format(passwd=passwd), re.I)
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