#coding:UTF-8
__author__ = 'dj'

from .data_extract import web_data, telnet_ftp_data, mail_data
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
        raw_data_list = web['raw_data'].split(b'\r\n\r\n')
        data_list = web['data'].split('\r\n\r\n')
        switch = False
        start = False
        type = ''
        for raw_data, data in zip(raw_data_list, data_list):
            if start:
                file_name = type + '_' + web['ip_port'].split(':')[0] + '_' + web['ip_port'].split(':')[1] + '_' + filename
                with open(folder + file_name, 'wb') as f:
                    f.write(raw_data.strip())
                web_list.append({'ip_port':web['ip_port'].split(':')[0]+':'+web['ip_port'].split(':')[1], 'filename':(folder+file_name), 'size':'%.2f'%(os.path.getsize(folder+file_name)/1024.0)})
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
        if "PASV" in cmd_data:  #PASV模式,通过Web浏览器访问模式
            pattern_pasv = re.compile(r'PASV(.*?)RETR(.*?)150', re.S)
            result = pattern_pasv.findall(cmd_data)
            if not result:
                continue
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
                with open(folder + file_name, 'wb') as f:
                    f.write(ftp['raw_data'])
                count += 1
                ftp_list.append({'ip_port':ftp['ip_port'].split(':')[0] + ':' + ftp['ip_port'].split(':')[1], 'filename':folder+file_name, 'size':'%.2f'%(os.path.getsize(folder+file_name)/1024.0)})
        elif 'PORT' in cmd_data:  #PORT模式,通过终端访问模式
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
                with open(folder + file_name, 'wb') as f:
                    f.write(ftpdata['raw_data'])
                ftp_list.append({'ip_port':ftpdata['ip_port'].split(':')[0] + ':' + ftpdata['ip_port'].split(':')[1], 'filename':folder+file_name, 'size':'%.2f'%(os.path.getsize(folder+file_name)/1024.0)})
        else:
            pass
    return ftp_list

#填充不符合规范的base64数据
def base64padding(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += '='* missing_padding
    return data

#mail文件
def mail_file(PCAPS, host_ip, folder):
    filename_p = re.compile(r'filename="(.*?)"', re.S)
    charset = 'UTF-8'
    mail_list = list()
    maildata = mail_data(PCAPS, host_ip)
    for mail in maildata:
        file_dict = OrderedDict()
        data_list = mail['data'].split('\r\n\r\n')
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
                file_dict[mail['ip_port'].split(':')[0]+'_'+mail['ip_port'].split(':')[1]+'_'+filename] = filedata
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
        for filename, filedata in file_dict.items():
            mode = 'wb'
            encoding = None
            if isinstance(filedata, str):
                mode = 'w'
                encoding = 'UTF-8'
            elif isinstance(filedata, bytes):
                mode = 'wb'
                encoding = None
            with open(folder+filename, mode, encoding=encoding) as f:
                f.write(filedata)
            mail_list.append({'ip_port':filename.split('_')[0]+':'+filename.split('_')[1], 'filename':folder+filename, 'size':'%.2f'%(os.path.getsize(folder+filename)/1024.0)})
    return mail_list

#所有二进制文件
def all_files(PCAPS, folder):
    file_header = dict()
    with open('./app/utils/protocol/FILES', 'r', encoding='UTF-8') as f:
        lines = f.readlines()
    for line in lines:
        file_header[line.split(':')[0].strip()] = line.split(':')[1].strip()
    sessions = PCAPS.sessions()
    allfiles_dict = OrderedDict()
    allpayloads_dict = OrderedDict()
    for sess, ps in sessions.items():
        payload = b''
        for p in ps:
            if p.haslayer(Raw):
                payload += p[Raw].load
            if payload:
                allpayloads_dict[sess] = payload
    i = 0
    for sess, payload in allpayloads_dict.items():
        datas = payload.split(b'\r\n\r\n')
        for data in datas:
            d = binascii.hexlify(data.strip())
            for header, suffix in file_header.items():
                if d.startswith(header.encode('UTF-8')):
                    filename = str(i) + suffix
                    with open(folder+filename, 'wb') as f:
                        f.write(binascii.unhexlify(d))
                    allfiles_dict[filename] = sess
                    i += 1
    return allfiles_dict