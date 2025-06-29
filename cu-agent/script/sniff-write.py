from scapy.all import sniff, wrpcap, Packet
import threading
import queue
import time

pkt_queue = queue.Queue()
capture_interface = "eth0"

DUMP_INTERVAL = 1
FILE_PREFIX = "capture"

file_index = 0
lock = threading.Lock()

def packet_handler(pkt: Packet):
    pkt_queue.put(pkt)

def pcap_writer_loop():
    global file_index
    while True:
        time.sleep(DUMP_INTERVAL)

        buffer = []
        while not pkt_queue.empty():
            buffer.append(pkt_queue.get())

        if buffer:
            with lock:
                # filename = f"{FILE_PREFIX}_{file_index}.pcap"
                filename = f"cu-agent/pcap/raw-pcap/{FILE_PREFIX}.pcap"
                wrpcap(filename, buffer)
                # print(f"[CU_Agent] 寫入 {filename}，共 {len(buffer)} 筆封包")
                file_index += 1
        # else:
            # print("[CU_Agent] 此時段無封包")


def main():
    writer_thread = threading.Thread(target=pcap_writer_loop, daemon=True)
    writer_thread.start()

    sniff(
        iface=capture_interface,
        # filter="src net 10.0.0.0/24",
        prn=packet_handler,
        store=False,
        promisc=True
    )


if __name__ == "__main__":
    main()
