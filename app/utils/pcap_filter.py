# coding:UTF-8
import collections
import sys
import tempfile


# 返回所有的数据包列表
def get_all_pcap(PCAPS, PD):
    pcaps = collections.OrderedDict()
    count = 0
    for p in PCAPS:
        count += 1
        pcap = PD.ether_decode(p)
        pcaps[count] = pcap
    return pcaps


def get_filter_pcap(PCAPS, PD, key, value):
    pcaps = collections.OrderedDict()
    count = 0
    for p in PCAPS:
        count += 1
        pcap = PD.ether_decode(p)
        if key == 'Procotol':
            if value == 'ICMP':
                if value in pcap[key].upper():
                    pcaps[count] = pcap
            else:
                if value == pcap[key].upper():
                    pcaps[count] = pcap
        else:
            if value in pcap[key].upper():
                pcaps[count] = pcap
    return pcaps


# 协议过滤器
def proto_filter(filter_type, value, PCAPS, PD):
    if filter_type == u'all':
        pcaps = get_all_pcap(PCAPS, PD)
    elif filter_type == u'proto':
        if value:
            key = 'Procotol'
            value = str(value).strip().upper()
            pcaps = get_filter_pcap(PCAPS, PD, key, value)
        else:
            pcaps = get_all_pcap(PCAPS, PD)
    elif filter_type == u'ipsrc':
        if value:
            key = 'Source'
            value = str(value).strip().upper()
            pcaps = get_filter_pcap(PCAPS, PD, key, value)
        else:
            pcaps = get_all_pcap(PCAPS, PD)
    elif filter_type == u'ipdst':
        if value:
            key = 'Destination'
            value = str(value).strip().upper()
            pcaps = get_filter_pcap(PCAPS, PD, key, value)
        else:
            pcaps = get_all_pcap(PCAPS, PD)
    else:
        pcaps = get_all_pcap(PCAPS, PD)
    return pcaps


def showdata_from_id(PCAPS, dataid):
    pcap = PCAPS[dataid]
    # 输出重定向数据
    show_temp_name = tempfile.NamedTemporaryFile(prefix='show_', dir='/tmp')
    old = sys.stdout
    show_file = open(show_temp_name.name, 'w')
    sys.stdout = show_file
    pcap.show()
    sys.stdout = old
    show_file.close()
    # 读取数据
    with open(show_temp_name.name, 'r') as showf:
        data = showf.read()
    result = data.strip().split('###')[1:]
    html = '''
            <div class="accordion-group">
                <div class="accordion-heading">
                    <b><a class="accordion-toggle" data-toggle="collapse" data-parent="#accordion" href="#collapse{id}">
                        {proto}
                    </a></b><br>
                    </div>
                    <div id="collapse{id}" class="accordion-body collapse" style="height: 0px; ">
                    <div class="accordion-inner">
                        {values}
                    </div>
                </div>
            </div>
'''
    all_html = ''
    id = 0
    for proto, value in zip(result[::2], result[1::2]):
        id += 1
        html_proto = proto.strip()[1:-1].strip()
        html_values = ''
        values = value.strip().split('\n')
        for v in values:
            val = v.split('  =')
            if len(val) == 2:
                html_values += '<b>{0} = {1}</b><br>'.format(val[0].strip(), val[1].strip())
            elif len(val) == 1:
                html_values += '<b>{0} = {1}</b><br>'.format('options', 'None')
        all_html += html.format(proto=html_proto, values=html_values, id=str(id))
    return all_html
