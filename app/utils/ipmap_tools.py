#coding:UTF-8
__author__ = 'dj'

from scapy.all import *
import requests
import os
import geoip2.database

#获取本机外网IP
def getmyip():
    try:
        headers = {'User-Agent': 'Baiduspider+(+http://www.baidu.com/search/spider.htm'}
        ip = requests.get('http://icanhazip.com', headers=headers).text
        return ip.strip()
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