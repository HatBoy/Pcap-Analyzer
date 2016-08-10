#coding:UTF-8
__author__ = 'dj'

import os

#获取网卡名称
def get_ifaces():
    ifaces_list = os.popen('ifconfig').read().split('\n\n')
    ifaces_list = [i for i in ifaces_list if i]
    iface_list = list()
    for ifaces in ifaces_list:
        iface = ifaces.split('\n')[0].split()[0].strip()
        ip = ifaces.split('\n')[1].split()[1].split(':')[-1].strip()
        mac = ifaces.split('\n')[0].split()[-1].strip()
        receive = ifaces.split('\n')[-1].split()[1][1:] + ifaces.split('\n')[-1].split()[2][:-1]
        send = ifaces.split('\n')[-1].split()[-2][1:] + ifaces.split('\n')[-1].split()[-1][:-1]
        iface_list.append({'iface':iface, 'ip':ip, 'mac':mac.decode('utf-8'), 'receive':receive, 'send':send})
    return iface_list