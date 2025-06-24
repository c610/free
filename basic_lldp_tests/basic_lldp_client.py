#!/usr/bin/env python3
import sys
import socket
import struct
import time


def make_tlv(tlv_type, tlv_value):
    length = len(tlv_value)
    tlv_header = ((tlv_type & 0x7f) << 9) | (length & 0x1ff)
    return struct.pack('!H', tlv_header) + tlv_value

def build_lldp_packet():
    # TLV 1: Chassis ID, subtype 4 (MAC address)
    chassis_tlv = make_tlv(1, b'\x04' + b'\x11\x22\x33\x44\x55\x66')

    # TLV 2: Port ID, subtype 5 (interface name)
    port_tlv = make_tlv(2, b'\x05' + b'eth0')

    # TLV 3: TTL, 2 bajty (seconds)
    ttl_tlv = make_tlv(3, struct.pack('!H', 120))

    # TLV 0: End of LLDPDU
    end_tlv = struct.pack('!H', 0)

    return chassis_tlv + port_tlv + ttl_tlv + end_tlv


def send_lldp(interface):
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    raw_socket.bind((interface, 0))

    dst_mac = b'\x01\x80\xc2\x00\x00\x0e'  # LLDP multicast address
    src_mac = b'\xaa\xbb\xcc\xdd\xee\xff'  # arbitrary source MAC

    ethertype = b'\x88\xcc'

    lldp_payload = build_lldp_packet()
    ethernet_frame = dst_mac + src_mac + ethertype + lldp_payload

    print(f"[+] Wysyłanie LLDP przez interfejs {interface}")
    raw_socket.send(ethernet_frame)

    # Odbieranie odpowiedzi (może być pusto!)
    raw_socket.settimeout(5)
    try:
        while True:
            pkt = raw_socket.recv(1500)
            if pkt[12:14] == b'\x88\xcc':
                print("[*] Otrzymano LLDP:")
                print(pkt.hex())
    except socket.timeout:
        print("[!] Brak odpowiedzi LLDP.")
    finally:
        raw_socket.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Użycie: sudo python3 {sys.argv[0]} <interfejs>")
        sys.exit(1)

    send_lldp(sys.argv[1])
