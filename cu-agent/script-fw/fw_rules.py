from netfilterqueue import NetfilterQueue
import scapy.all as scapy
from scapy.contrib.gtp import GTP_U_Header
import json


# all_ue_ip = [f"10.0.0.{i}" for i in range(2,256)]
current_connect_ue = {} # imsi: ip, imei, ...
blacklist_ip = set()
blacklist_imsi = set()

def get_current_ue():
    global current_connect_ue
    with open("/opt/oai-gnb/cu-agent/ue_list.json", 'r', encoding='utf-8') as f:
        current_connect_ue = json.load(f)

def get_ip_blacklist():
    global blacklist_ip
    with open("/opt/oai-gnb/cu-agent/ip_blacklist.json", 'r', encoding='utf-8') as f:
        blacklist_ip = set(json.load(f))

def get_imsi_blacklist():
    global blacklist_imsi
    with open("/opt/oai-gnb/cu-agent/imsi_blacklist.json", 'r', encoding='utf-8') as f:
        blacklist_imsi = set(json.load(f))


def extract_inner_ip(pkt):
    """從 GTP payload 遞迴找出最內層 IP 封包"""
    layer = pkt
    while layer:
        if isinstance(layer, scapy.IP):
            return layer
        layer = layer.payload
    return None

def process(pkt):
    scapy_packet = scapy.IP(pkt.get_payload())
    if not scapy_packet.payload:
        pkt.drop()
        return

    global current_connect_ue
    global blacklist_ip
    global blacklist_imsi
    get_current_ue()
    get_ip_blacklist()
    get_imsi_blacklist()

    inner_ip = extract_inner_ip(scapy_packet[GTP_U_Header])
    try:
        src_ip = inner_ip.src
    except:
        pkt.drop()
        return

    for ue in current_connect_ue.keys():
        if current_connect_ue[ue]["ue_ip"] == src_ip:
            ## check IMSI is in blacklist
            if ue in blacklist_imsi:
                pkt.drop()
                return
            ## check IP is in blacklist
            if src_ip in blacklist_ip:
                blacklist_imsi.append(ue)
                pkt.drop()
                with open("/opt/oai-gnb/cu-agent/imsi_blacklist.json", "w") as f:
                    json.dump(blacklist_imsi, f, indent=4)  # indent=4 讓格式更易讀
                return
    pkt.accept()
    return


nfq = NetfilterQueue()
nfq.bind(1, process)

try:
    print("FW...")
    nfq.run()
except KeyboardInterrupt:
    nfq.unbind()
