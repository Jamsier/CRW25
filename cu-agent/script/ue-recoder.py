"""
Decode NGAP to fint the UE TMSI <-> IP Address pair
"""
import scapy.all as scapy
from pycrate_asn1rt.utils import *
from pycrate_asn1dir import F1AP, NGAP, RRCNR
from pycrate_asn1dir import E2AP
from pycrate_mobile.NAS5G import *
import binascii
from binascii import hexlify, unhexlify
import socket
import time
from datetime import datetime
import json


ngap_related_ip = ['192.168.70.150', '192.168.70.132']
unique_ue_list = {}      # imsi: imei, guti, tmsi, ue_ip
ran_amf_ngap_id_idx = {} # (ran ue id, amf ue id): imsi


def find_imsi(nas_msg):
    plmn_start = nas_msg.find("<PLMN : ")
    if plmn_start != -1:
        plmn_start = plmn_start + len("<PLMN : ")
        plmn_end = nas_msg[plmn_start:].find(">") + plmn_start
        plmn = nas_msg[plmn_start:plmn_end]
    else:
        return None

    ## msin
    msin_start = nas_msg.find("<MSIN : ")
    if msin_start != -1:
        msin_start = msin_start + len("<MSIN : ")
        msin_end = nas_msg[msin_start:].find(">") + msin_start
        msin = nas_msg[msin_start:msin_end]
    else:
        return None
    imsi = plmn + msin
    return imsi


def find_imei(nas_msg):
    imeisv_start = nas_msg.find("### IMEISV ###")
    if imeisv_start != -1:
        imeisv_start = imeisv_start + len("### IMEISV ###")
        imeisv_digit1_s = nas_msg[imeisv_start:].find("<Digit1 : ") + len("<Digit1 : ") + imeisv_start
        imeisv_digit1_e = nas_msg[imeisv_digit1_s:].find(">") + imeisv_digit1_s
        imeisv_digit1 = nas_msg[imeisv_digit1_s:imeisv_digit1_e]

        imeisv_digits_s = nas_msg[imeisv_start:].find("<Digits : ") + len("<Digits : ") + imeisv_start
        imeisv_digits_e = nas_msg[imeisv_digits_s:].find(">") + imeisv_digits_s
        imeisv_digits = nas_msg[imeisv_digits_s:imeisv_digits_e]

        imeisv = imeisv_digit1 + imeisv_digits
        return imeisv
    else:
        return None


def find_guti(nas_msg):
    """example of 5g guti and 5g tmsi
        ### 5GSID ###
        <ind : 0xf>
        <spare : 0>
        <Type : 2 (5G-GUTI)>
        <PLMN : 00101>
        <AMFRegionID : 1>
        <AMFSetID : 1>
        <AMFPtr : 1>
        <5GTMSI : 0xfeb79840>
    """
    guti = nas_msg.find("### GUTI ###")
    if guti != -1:
        plmn_s = nas_msg[guti:].find("<PLMN : ") + len("<PLMN : ") + guti
        plmn_e = nas_msg[plmn_s:].find(">") + plmn_s
        plmn = nas_msg[plmn_s:plmn_e]

        amf_region_id_s = nas_msg[guti:].find("<AMFRegionID : ") + len("<AMFRegionID : ") + guti
        amf_region_id_e = nas_msg[amf_region_id_s:].find(">") + amf_region_id_s
        amf_region_id = nas_msg[amf_region_id_s:amf_region_id_e]
        if len(amf_region_id) == 1: amf_region_id = "0" + amf_region_id

        amf_set_id_s = nas_msg[guti:].find("<AMFSetID : ") + len("<AMFSetID : ") + guti
        amf_set_id_e = nas_msg[amf_set_id_s:].find(">") + amf_set_id_s
        amf_set_id = nas_msg[amf_set_id_s:amf_set_id_e]
        if len(amf_set_id) < 4: amf_set_id = (4-len(amf_set_id))*"0" + amf_set_id

        amf_ptr_s = nas_msg[guti:].find("<AMFPtr : ") + len("<AMFPtr : ") + guti
        amf_ptr_e = nas_msg[amf_ptr_s:].find(">") + amf_ptr_s
        amf_ptr = nas_msg[amf_ptr_s:amf_ptr_e]
        if len(amf_ptr) == 1: amf_ptr = "0" + amf_ptr

        tmsi5g_s = nas_msg[guti:].find("<5GTMSI : ") + len("<5GTMSI : ") + guti
        tmsi5g_e = nas_msg[tmsi5g_s:].find(">") + tmsi5g_s
        tmsi5g = nas_msg[tmsi5g_s:tmsi5g_e] # 0xfeb79840
        
        ## hex to int
        tmsi5g = int(tmsi5g, 16)
        tmsi5g = str(tmsi5g)

        guti = {
            "plmn": plmn,
            "amf_region_id": amf_region_id,
            "amf_set_id": amf_set_id,
            "amf_ptr": amf_ptr,
            "5g_tmsi": tmsi5g
        }
        return guti
    else:
        return None


def process_pkt(pkt):
    global ngap_related_ip, unique_ue_list, ran_amf_ngap_id_idx

    print(".", end="", flush=True)
    if pkt.haslayer(scapy.SCTP):
        sctp_pkt = pkt[scapy.SCTP]
        sctp_message_type=sctp_pkt[scapy.SCTP].type
        sctp_payload = sctp_pkt[scapy.SCTP].payload

        # if is NGAP
        if pkt[scapy.SCTP].haslayer('SCTPChunkData') and pkt[scapy.IP].dst in ngap_related_ip and pkt[scapy.IP].src in ngap_related_ip:
            # print(f"\n====================== [NGAP_PDU] ======================")
            payload = sctp_pkt[1].data
            PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
            PDU.from_aper(payload)
            content = PDU.to_asn1()     # string
            # print(content)

            ########################## get AMF UE ID, RAN UE ID ############################
            amf_ue_ngap_id = None
            ran_ue_ngap_id = None
            amf_ue_ngap_id_s = content.find("value AMF-UE-NGAP-ID: ")
            if amf_ue_ngap_id_s != -1:
                amf_ue_ngap_id_s = amf_ue_ngap_id_s + len("value AMF-UE-NGAP-ID: ")
                amf_ue_ngap_id_e = content[amf_ue_ngap_id_s:].find("\n") + amf_ue_ngap_id_s
                amf_ue_ngap_id = content[amf_ue_ngap_id_s:amf_ue_ngap_id_e]

            ran_ue_ngap_id_s = content.find("value RAN-UE-NGAP-ID: ")
            if ran_ue_ngap_id_s != -1:
                ran_ue_ngap_id_s = ran_ue_ngap_id_s + len("value RAN-UE-NGAP-ID: ")
                ran_ue_ngap_id_e = content[ran_ue_ngap_id_s:].find("\n") + ran_ue_ngap_id_s
                ran_ue_ngap_id = content[ran_ue_ngap_id_s:ran_ue_ngap_id_e]
                
            # print(f"AMF UE ID: {amf_ue_ngap_id}")
            # print(f"RAN UE ID: {ran_ue_ngap_id}")

            ################################# get NAS PDU #################################
            nas_msg_start = content.find("value NAS-PDU: '")
            if nas_msg_start != -1:
                nas_msg_start = nas_msg_start + len("value NAS-PDU: '")
                nas_msg_end = content[nas_msg_start:].find("'H") + nas_msg_start
                nas_msg_hex = content[nas_msg_start:nas_msg_end]
                # print(nas_msg_hex)
                # print(nas_msg_bytes)

                ### decode NAS PDU
                msg, err = parse_NAS5G(unhexlify(nas_msg_hex))
                nas_msg = msg.show()
                # print(nas_msg)

                ### IMSI
                imsi = find_imsi(nas_msg)
                if imsi and imsi not in unique_ue_list:
                    now = datetime.now()
                    now = now.strftime("%Y-%m-%d %H:%M:%S")
                    unique_ue_list[imsi] = {
                        "imei": None,
                        "5g-guti": None,
                        "ue_ip": None,
                        "connect_time": now
                    }

                ### TMEI, 5G-GUTI, 5G-TMSI
                nas_msg_2_start = nas_msg.find("<NASMessage : ")
                if nas_msg_2_start != -1:
                    nas_msg_2_start = nas_msg_2_start + len("<NASMessage : ")
                    nas_msg_2_end = nas_msg[nas_msg_2_start:].find(">") + nas_msg_2_start
                    nas_msg_hex_2 = nas_msg[nas_msg_2_start+2:nas_msg_2_end]
                    nas_msg2, err = parse_NAS5G(unhexlify(nas_msg_hex_2))
                    nas_msg2 = nas_msg2.show()
                    # print(nas_msg2)

                    ### IMSI
                    imsi = find_imsi(nas_msg2)
                    if amf_ue_ngap_id and ran_ue_ngap_id and imsi:
                        ran_amf_ngap_id_idx[(amf_ue_ngap_id, ran_ue_ngap_id)] = imsi

                    ### IMEI
                    imei = find_imei(nas_msg2)
                    if imei:
                        unique_ue_list[imsi]["imei"] = imei[:-2]

                    ### 5G-GUTI
                    if not imsi:
                        imsi = ran_amf_ngap_id_idx[(amf_ue_ngap_id, ran_ue_ngap_id)]
                    guti = find_guti(nas_msg2)
                    if guti:
                        unique_ue_list[imsi]["5g-guti"] = guti


            ################################ get PDU session ################################
            pdu_session = content.find("value PDUSessionResourceSetupListSUReq: ")
            if pdu_session != -1:
                pdu_nas_msg_s = content.find("pDUSessionNAS-PDU '") + len("pDUSessionNAS-PDU '")
                pdu_nas_msg_e = content[pdu_nas_msg_s:].find("'H") + pdu_nas_msg_s
                pdu_nas_msg_hex = content[pdu_nas_msg_s:pdu_nas_msg_e]
                nas_msg, err = parse_NAS5G(unhexlify(pdu_nas_msg_hex))
                nas_msg = nas_msg.show()

                nas_msg_2_s = nas_msg.find("<NASMessage : 0x") + len("<NASMessage : 0x")
                nas_msg_2_e = nas_msg[nas_msg_2_s:].find(">") + nas_msg_2_s
                nas_msg_2_hex = nas_msg[nas_msg_2_s:nas_msg_2_e]
                nas_msg2, err = parse_NAS5G(unhexlify(nas_msg_2_hex))
                nas_msg2 = nas_msg2.show()

                ## find ipv4
                ipv4_start = nas_msg2.find("<IPv4 : 0x") + len("<IPv4 : 0x")
                ipv4_end = nas_msg2[ipv4_start:].find(">") + ipv4_start
                ipv4 = nas_msg2[ipv4_start:ipv4_end]
                ipv4 = socket.inet_ntoa(binascii.unhexlify(ipv4))
                imsi = ran_amf_ngap_id_idx[(amf_ue_ngap_id, ran_ue_ngap_id)]

                # print(amf_ue_ngap_id, ran_ue_ngap_id, imsi, ipv4)
                unique_ue_list[imsi]['ue_ip'] = ipv4

            ################################# ue deregister #################################
            ue_deregister = content.find("value UEContextReleaseComplete: ")
            if ue_deregister != -1:
                ## delete key (amf_ue_ngap_id, ran_ue_ngap_id)
                imsi = ran_amf_ngap_id_idx[(amf_ue_ngap_id, ran_ue_ngap_id)]
                unique_ue_list.pop(imsi)
                ran_amf_ngap_id_idx.pop((amf_ue_ngap_id, ran_ue_ngap_id))

            print(f"[CU_Agent] {unique_ue_list}")
            # print(f"[CU_Agent] {ran_amf_ngap_id_idx}")
            with open("cu-agent/ue_list.json", "w") as f:
                json.dump(unique_ue_list, f, indent=4)

            # time.sleep(0.1)

print("Starting sniff on eth0...")
scapy.sniff(iface="eth0", prn=process_pkt, store=False, lfilter=lambda x: True)
