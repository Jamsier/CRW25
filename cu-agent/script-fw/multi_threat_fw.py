from netfilterqueue import NetfilterQueue
import scapy.all as scapy
from scapy.contrib.gtp import GTP_U_Header
import json
import threading
import queue
import time

# 設定工作執行緒數量
NUM_WORKERS = 6
pkt_queue = queue.Queue()

# 全域快取
current_connect_ue = {}
blacklist_ip_set = set()
blacklist_imsi = []
blacklist_imsi_set = set()

last_update_time = 0
update_interval = 1

def get_current_ue():
    global current_connect_ue
    with open("/opt/oai-gnb/cu-agent/ue_list.json", 'r', encoding='utf-8') as f:
        current_connect_ue = json.load(f)

def get_ip_blacklist():
    global blacklist_ip, blacklist_ip_set
    with open("/opt/oai-gnb/cu-agent/ip_blacklist.json", 'r', encoding='utf-8') as f:
        blacklist_ip_set = set(json.load(f))

def get_imsi_blacklist():
    global blacklist_imsi, blacklist_imsi_set
    with open("/opt/oai-gnb/cu-agent/imsi_blacklist.json", 'r', encoding='utf-8') as f:
        blacklist_imsi = json.load(f)
        blacklist_imsi_set = set(blacklist_imsi)

def maybe_refresh_blacklist():
    global last_update_time
    now = time.time()
    if now - last_update_time > update_interval:
        get_current_ue()
        get_ip_blacklist()
        get_imsi_blacklist()
        last_update_time = now

def extract_inner_ip(pkt):
    layer = pkt
    while layer:
        if isinstance(layer, scapy.IP):
            return layer
        layer = layer.payload
    return None

def process_packet():
    while True:
        pkt = pkt_queue.get()
        if pkt is None:
            break  # 停止訊號

        scapy_packet = scapy.IP(pkt.get_payload())
        if not scapy_packet.payload:
            print("x", end="")
            pkt.drop()
            pkt_queue.task_done()
            continue

        maybe_refresh_blacklist()

        try:
            inner_ip = extract_inner_ip(scapy_packet[GTP_U_Header])
            src_ip = inner_ip.src
        except:
            print("x", end="")
            pkt.drop()
            pkt_queue.task_done()
            continue

        for imsi in current_connect_ue.keys():
            if current_connect_ue[imsi]["ue_ip"] == src_ip:
                if imsi in blacklist_imsi_set:
                    print("x", end="")
                    pkt.drop()
                    pkt_queue.task_done()
                    break

                if src_ip in blacklist_ip_set:
                    print("x", end="")
                    if imsi not in blacklist_imsi_set:
                        blacklist_imsi.append(imsi)
                        blacklist_imsi_set.add(imsi)
                        with open("/opt/oai-gnb/cu-agent/imsi_blacklist.json", "w") as f:
                            json.dump(blacklist_imsi, f, indent=4)
                    pkt.drop()
                    pkt_queue.task_done()
                    break
        else:
            pkt.accept()
            pkt_queue.task_done()

def enqueue(pkt):
    pkt.retain()
    pkt_queue.put(pkt)

# 啟動 Worker 執行緒
workers = []
for _ in range(NUM_WORKERS):
    t = threading.Thread(target=process_packet)
    t.daemon = True
    t.start()
    workers.append(t)

# 綁定 NetfilterQueue
nfq = NetfilterQueue()
nfq.bind(1, enqueue)

try:
    print("Firewall is running with multithreading...")
    nfq.run()
except KeyboardInterrupt:
    print("\nStopping firewall...")
    nfq.unbind()

    # 通知 Worker 停止
    for _ in range(NUM_WORKERS):
        pkt_queue.put(None)

    for t in workers:
        t.join()
