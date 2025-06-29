import scapy.all as scapy
from scapy.contrib.gtp import GTP_U_Header
import os

VALID_IP = [f"10.0.0.{ip}" for ip in range(1, 255)]


def extract_inner_ip(pkt):
    """從 GTP payload 遞迴找出最內層 IP 封包"""
    layer = pkt
    while layer:
        if isinstance(layer, scapy.IP):
            return layer
        layer = layer.payload
    return None


def main():
    pcap_dir = "cu-agent/pcap/raw-pcap"
    output_dir = "cu-agent/pcap/stripped-gtp"
    
    SRC_MAC = "00:11:22:33:44:55"
    DST_MAC = "66:77:88:99:aa:bb"
    
    targets = os.listdir(pcap_dir)
    print(f"Found {len(os.listdir(pcap_dir))} pcap file: {os.listdir(pcap_dir)}")
    
    # check = input("Start processing? (Y/n)")
    # if check == 'n':
    #     return
    
    for pcap_file in targets:
        print(f"Start processing {pcap_file}", end=" | ")
        pcap_file_path = os.path.join(pcap_dir, pcap_file)
        packets = scapy.rdpcap(pcap_file_path)
        new_packets = []
        
        for pkt in packets:
            if not pkt.payload:
                continue
            if pkt.haslayer(scapy.IP):
                ether_type = 0x0800  # IPv4
                payload = pkt[scapy.IP]
            elif pkt.haslayer(scapy.IPv6):
                ether_type = 0x86DD  # IPv6
                payload = pkt[scapy.IPv6]
            elif pkt.haslayer(scapy.ARP):
                ether_type = 0x0806  # ARP
                payload = pkt[scapy.ARP]
            else:
                ether_type = 0x0000
                payload = pkt.payload
            ether = scapy.Ether(src=SRC_MAC, dst=DST_MAC, type=ether_type)
            
            if pkt.haslayer(GTP_U_Header):
                inner_ip = extract_inner_ip(pkt[GTP_U_Header])
                if inner_ip:
                    if inner_ip.src not in VALID_IP:
                        continue
                    cooked = scapy.CookedLinuxV2() / inner_ip  # 包一層 CookedLinuxV2
                    cooked.time = pkt.time               # 保留原封包時間
                    cooked = ether / cooked[scapy.IP]
                    new_packets.append(cooked)
                else:
                    pkt = ether / pkt[scapy.IP]
                    new_packets.append(pkt)
            # else:
            #     pkt = ether / payload
            #     new_packets.append(pkt)

        save_path = f"{output_dir}/{pcap_file.split('.')[0]}-stripped.pcap"
        scapy.wrpcap(save_path, new_packets)
        print(f"Save processed pcap to {save_path}")


if __name__ == "__main__":
    main()