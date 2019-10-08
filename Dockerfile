FROM python:3.7
EXPOSE 8000

VOLUME /home/dj /var/log/gunicorn

RUN apt-get update && apt-get install tcpdump graphviz imagemagick -y &&\
    pip install scapy Flask Flask-WTF geoip2 pyx requests gunicorn

COPY ./ /

CMD gunicorn -c deploy_config.py run:app
