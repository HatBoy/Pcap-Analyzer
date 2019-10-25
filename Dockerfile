FROM python:3.7
EXPOSE 8000

VOLUME /home/dj/PCAP /var/log/gunicorn /home/dj/Files/PDF \
       /home/dj/Files/All /home/dj/Files/FTP /home/dj/Files/Mail /home/dj/Files/Web

RUN apt-get update && apt-get install tcpdump graphviz imagemagick -y &&\
    pip install --no-cache-dir scapy Flask Flask-WTF geoip2 pyx requests gunicorn

COPY ./ /

CMD gunicorn -c deploy_config.py run:app
