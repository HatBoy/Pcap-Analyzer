#coding:UTF-8
__author__ = 'dj'

from scapy.all import *
import json
import urllib2
import urllib
import os
import geoip2.database

#获取本机外网IP
def getmyip():
    try:
        req = urllib2.Request(url='http://ip.taobao.com/service/getIpInfo2.php', data=urllib.urlencode({'ip':'myip'}))
        html = urllib2.urlopen(req, timeout=5).read()
        data = json.loads(html)
        myip = data['data']['ip']
        return myip
    except:
        return None


#获取经纬度
def get_geo(ip):
    reader = geoip2.database.Reader(os.getcwd()+'/app/utils/GeoIP/GeoLite2-City.mmdb')
    try:
        response = reader.city(ip)
        city_name = response.country.names['zh-CN']+response.city.names['zh-CN']
        longitude = response.location.longitude
        latitude = response.location.latitude
        return [city_name, longitude, latitude]
    except:
        return None

#IP地图数据
def get_ipmap(PCAPS, host_ip):
    geo_dict = dict()
    ip_value_dict = dict()
    ip_value_list = list()
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            src = pcap.getlayer(IP).src
            dst = pcap.getlayer(IP).dst
            pcap_len = len(corrupt_bytes(pcap))
            if src == host_ip:
                oip = dst
            else:
                oip = src
            if oip in ip_value_dict:
                ip_value_dict[oip] += pcap_len
            else:
                ip_value_dict[oip] = pcap_len
    for ip, value in ip_value_dict.items():
        geo_list = get_geo(ip)
        if geo_list:
            geo_dict[geo_list[0]] = [geo_list[1], geo_list[2]]
            Mvalue = str(float('%.2f'%(value/1024.0)))+':'+ip
            ip_value_list.append({geo_list[0]:Mvalue})
        else:
            pass
    return [geo_dict, ip_value_list]