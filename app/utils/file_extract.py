#coding:UTF-8
__author__ = 'dj'

from data_extract import web_data, telnet_ftp_data, mail_data
from scapy.all import *
from collections import OrderedDict
import base64
import os
import re
import binascii

#web文件
def web_file(PCAPS, host_ip, folder):
    web_list = list()
    webdata = web_data(PCAPS, host_ip)
    for web in webdata:
        data_list = web['data'].split('\r\n\r\n')
        switch = False
        start = False
        type = ''
        for data in data_list:
            if start:
                file_name = type + '_' + web['ip_port'].split(':')[0] + '_' + web['ip_port'].split(':')[1] + '_' + filename
                with open(folder + file_name, 'w') as f:
                    f.write(data.strip())
                web_list.append({'ip_port':web['ip_port'].split(':')[0]+':'+web['ip_port'].split(':')[1], 'filename':(folder+file_name).decode('utf-8'), 'size':'%.2f'%(os.path.getsize(folder+file_name)/1024.0)})
                start = False
                switch = False
            if switch:
                if 'HTTP/1.1 200 OK' in data and 'GET' not in data and type == 'GET':
                    start = True
                    switch = False
                elif 'filename' in data and type == 'POST':
                    filename = re.search(r'filename="(.*)?"', data).group(1)
                    start = True
                    switch = False
                else:
                    filename = ''
                    switch = False
                    start = False
            if 'GET' in data and 'HTTP/1.1' in data:
                try:
                    filename = data.split('\r\n')[0].split(' ')[1].split('/')[-1]
                    if re.match(r'^[A-Za-z0-9_]*?\.[A-Za-z0-9_]*?$', filename):
                        filename = re.match(r'^[A-Za-z0-9_]*?\.[A-Za-z0-9_]*?$', filename).group()
                        switch = True
                        start = False
                        type = 'GET'
                except:
                    pass
            elif 'POST' in data and 'HTTP/1.1' in data:
                switch = True
                start = False
                type = 'POST'
            else:
                pass
    return web_list


#ftp文件
def ftp_file(PCAPS, host_ip, folder):
    ftp_list = list()
    ftp_cmd_data = telnet_ftp_data(PCAPS, host_ip, 21)
    port_file_list = list()
    for ftp_cmd in ftp_cmd_data:
        cmd_data = ftp_cmd['data']
        if "PASV" in cmd_data:  #PASV模式
            pattern_pasv = re.compile(r'PASV(.*?)RETR(.*?)150', re.S)
            result = pattern_pasv.findall(cmd_data)
            if 'LIST' in result[0][0]:
                start = 1
            else:
                start = 0
            for port, file in result:
                port = port.strip().split('(')[-1].split(')')[0].split(',')
                port = int(port[-2]) * 256 + int(port[-1])
                file = file.strip().split('/')[-1]
                port_file_list.append((port, file))
            port_list = list()
            filename_list = list()
            for port, filename in port_file_list:
                port_list.append(port)
                filename_list.append(filename)
            port = port_list[0]
            ftpdata = telnet_ftp_data(PCAPS, host_ip, port)
            count = 0
            for ftp in ftpdata[start:]:
                file_name = ftp['ip_port'].split(':')[0] + '_' + ftp['ip_port'].split(':')[1] + '_'+filename_list[count]
                with open(folder + file_name, 'w') as f:
                    f.write(ftp['data'])
                count += 1
                ftp_list.append({'ip_port':ftp['ip_port'].split(':')[0] + ':' + ftp['ip_port'].split(':')[1], 'filename':folder+file_name, 'size':'%.2f'%(os.path.getsize(folder+file_name)/1024.0)})
        elif 'PORT' in cmd_data:  #PORT模式
            pattern_port = re.compile(r'PORT(.*?)(RETR|STOR)(.*?)150', re.S)
            result = pattern_port.findall(cmd_data)
            for port, pattern, file in result:
                port = port.strip().split('\r\n')[-2].split(',')
                port = int(port[-2]) * 256 + int(port[-1])
                file = file.strip()
                port_file_list.append((port, file))
            for port, filename in port_file_list:
                ftpdata = telnet_ftp_data(PCAPS, host_ip, port)[0]
                file_name = ftpdata['ip_port'].split(':')[0] + '_' + ftpdata['ip_port'].split(':')[1] + '_'+filename
                with open(folder + file_name, 'w') as f:
                    f.write(ftpdata['data'])
                ftp_list.append({'ip_port':ftpdata['ip_port'].split(':')[0] + ':' + ftpdata['ip_port'].split(':')[1], 'filename':folder+file_name, 'size':'%.2f'%(os.path.getsize(folder+file_name)/1024.0)})
        else:
            pass
    return ftp_list


#mail文件
def mail_file(PCAPS, host_ip, folder):
    mail_list = list()
    maildata = mail_data(PCAPS, host_ip)
    for mail in maildata:
        file_dict = OrderedDict()
        data_list = mail['data'].split('\r\n')
        switch = False
        for data in data_list:
            if switch:
                if not data:
                    space += 1
                    if space == 2:
                        switch = False
                        file_dict[file_dict.keys()[-1]] = file_data
                else:
                    file_data += data
            if 'filename' in data:
                switch = True
                space = 0
                file_data = ''
                file_dict[mail['ip_port'].split(':')[0]+'_'+mail['ip_port'].split(':')[1]+'_'+data.split('=')[-1][1:-1]] = ''
        for filename, filedata in file_dict.items():
            with open(folder+filename, 'w') as f:
                f.write(base64.b64decode(filedata.strip()))
            mail_list.append({'ip_port':filename.split('_')[0]+':'+filename.split('_')[1], 'filename':folder+filename, 'size':'%.2f'%(os.path.getsize(folder+filename)/1024.0)})
    return mail_list

#所有二进制文件
def all_files(PCAPS, folder):
    file_header = dict()
    with open('./app/utils/protocol/FILES', 'r') as f:
        lines = f.readlines()
    for line in lines:
        file_header[line.split(':')[0].strip()] = line.split(':')[1].strip()
    sessions = PCAPS.sessions()
    allfiles_dict = OrderedDict()
    allpayloads_dict = OrderedDict()
    for sess, ps in sessions.items():
        payload = ''
        for p in ps:
            if p.haslayer(Raw):
                payload += p[Raw].load
            if payload:
                allpayloads_dict[sess] = payload
    i = 0
    for sess, payload in allpayloads_dict.items():
        datas = payload.split('\r\n\r\n')
        for data in datas:
            d = binascii.hexlify(data.strip())
            prefix = d[:10]
            for header, suffix in file_header.items():
                if re.match(header, prefix):
                    filename = str(i) + suffix
                    with open(folder+filename, 'wb') as f:
                        f.write(binascii.unhexlify(d))
                    allfiles_dict[filename] = sess
                    i += 1
    return allfiles_dict