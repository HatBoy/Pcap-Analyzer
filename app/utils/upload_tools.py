#coding:UTF-8
__author__ = 'dj'

import random

#上传后缀名校验
def allowed_file(filename):
    ALLOWED_EXTENSIONS = set(['pcap', 'cap'])
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

#获取文件后缀
def get_filetype(filename):
    return '.' + filename.rsplit('.', 1)[1]

#生成随机的字符串文件名
def random_name():
    return ''.join(random.sample('1234567890qazxswedcvfrtgbnhyujmkiolp', 10))