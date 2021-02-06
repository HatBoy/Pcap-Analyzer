# Pcap-Analyzer

## 更新说明
+ 将项目从Python2.X移植到Python3.X
+ 修复了多个Bug

## 主要功能
+ 1.展示数据包基本信息
+ 2.分析数据包协议
+ 3.分析数据包流量
+ 4.绘制出访问IP经纬度地图
+ 5.提取数据包中特定协议的会话连接（WEB，FTP，Telnet）
+ 6.提取会话中的敏感数据（密码）
+ 7.简单的分析数据包中的安全风险（WEB攻击，暴力破解）
+ 8.提取数据报中的特定协议的传输文件或者所有的二进制文件

## 效果展示
### 首页:
![Alt Text](https://github.com/HatBoy/Pcap-Analyzer/blob/master/images/index.png)

### 基本数据展示:
![Alt Text](https://github.com/HatBoy/Pcap-Analyzer/blob/master/images/basedata.png)

### 协议分析:
![Alt Text](https://github.com/HatBoy/Pcap-Analyzer/blob/master/images/protoanalyxer.png)

### 流量分析:
![Alt Text](https://github.com/HatBoy/Pcap-Analyzer/blob/master/images/flowanalyzer.png)

### 访问IP经纬度地图:
![Alt Text](https://github.com/HatBoy/Pcap-Analyzer/blob/master/images/ipmap.png)

### 会话提取:
![Alt Text](https://github.com/HatBoy/Pcap-Analyzer/blob/master/images/getdata.png)

### 攻击信息警告:
![Alt Text](https://github.com/HatBoy/Pcap-Analyzer/blob/master/images/attackinfo.png)

### 文件提取:
![Alt Text](https://github.com/HatBoy/Pcap-Analyzer/blob/master/images/getfiles.png)

## 安装部署过程:

+ 运行环境：Python 3.5.X
+ 操作系统：Linux (以Ubuntu 15.10为例)

### 1.Python相关环境配置（Ubuntu默认安装Python2.7不需要额外安装Python）
Python包管理器安装：sudo apt-get install python-setuptools python-pip

### 2.相关第三方依赖库安装：
+ sudo apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx
+ sudo pip3 install Flask
+ sudo pip3 install Flask-WTF
+ sudo pip3 install geoip2
+ sudo pip3 install pyx
+ sudo pip3 install requests
+ scapy的安装请参见官方文档，scapy的版本为2.4.0，2.4.0之后版本有较大的变化，可能导致不兼容

### 3.修改配置文件
注意修改config.py配置文件中的目录位置
+ UPLOAD_FOLDER = '/home/dj/PCAP/'     上传的PCAP文件保存的位置
+ FILE_FOLDER = '/home/dj/Files/'      提取文件时保存的位置，下面必须要有All、FTP、Mail、Web子目录，用于存放提取不同协议的文件
+ PDF_FOLDER = '/home/dj/Files/PDF/'   PCAP保存为PDF时保存的位置

### 4.服务器安装
+ Gunicorn服务器：pip3 install gunicorn
+ Nginx服务器：sudo apt-get install nginx
+ Nginx配置：修改/etc/nginx/nginx.conf文件，在http{}中添加下面代码：
```
server { 
listen 81; 
server_name localhost; 
access_log /var/log/nginx/access.log; 
error_log /var/log/nginx/error.log;

     location / {
        #root   html;
        #index  index.html index.htm;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
         proxy_set_header Host $http_host;
         proxy_pass http://127.0.0.1:8000;
    }

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   html;
    }
```

### 5.启动系统：
+ 进入系统所在目录：../pcap-analyzer
+ 通过Gunicorn服务器服务器启动系统，运行命令：gunicorn -c deploy_config.py run:app
+ 此时只能本地访问系统，地址：http://127.0.0.1:8000
+ 启动Nginx服务器：sudo service nginx start
+ 此时其他主机也可访问该系统，地址：http://服务器IP:81


## 分析优化
### 对数据包的分析结果的准确率可通过修改配置文件来提高，修正
+ 替换./app/utils/GeoIP/GeoLite2-City.mmdb的IP地址经纬度数据库文件能提高IP经纬度地图的准确率
+ 修改./app/utils/protocol/目录中的各个TCP/IP协议栈的表示号和对应的协议名称可修正协议分析结果
+ 修改./app/utils/waring/HTTP_ATTACK文件可提高数据包中HTTP协议攻击的准确率
