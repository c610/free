#!/usr/bin/env python3
import sys
import socket
import struct
import time
import argparse

def make_tlv(tlv_type, tlv_value):
    length = len(tlv_value)
    tlv_header = ((tlv_type & 0x7f) << 9) | (length & 0x1ff)
    return struct.pack('!H', tlv_header) + tlv_value

def build_lldp_packet(fuzz_field=None, fuzz_payload=b''):
    chassis = b'\x04' + b'\x11\x22\x33\x44\x55\x66'
    chassis_tlv = make_tlv(1, chassis)

    port = b'\x05' + b'Gig1/0/1'
    port_tlv = make_tlv(2, port)

    ttl_tlv = make_tlv(3, struct.pack('!H', 120))

    extra_tlv = b''
    if fuzz_field == "system-name":
        extra_tlv = make_tlv(5, fuzz_payload)
    elif fuzz_field == "system-description":
        extra_tlv = make_tlv(6, fuzz_payload)
    elif fuzz_field == "custom":
        oui = b'\x00\x12\xbb'  # Cisco OUI
        subtype = b'\x01'
        custom_value = oui + subtype + fuzz_payload
        extra_tlv = make_tlv(127, custom_value)

    end_tlv = struct.pack('!H', 0)
    return chassis_tlv + port_tlv + ttl_tlv + extra_tlv + end_tlv

def send_lldp(interface, fuzz_field, fuzz_payload):
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    raw_socket.bind((interface, 0))

    dst_mac = b'\x01\x80\xc2\x00\x00\x0e'
    src_mac = b'\xaa\xbb\xcc\xdd\xee\xff'
    ethertype = b'\x88\xcc'

    lldp_payload = build_lldp_packet(fuzz_field, fuzz_payload)
    ethernet_frame = dst_mac + src_mac + ethertype + lldp_payload

    print(f"[+] Sending LLDP (field: {fuzz_field}, payload len: {len(fuzz_payload)}) on {interface}")
    raw_socket.send(ethernet_frame)
    raw_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLDP Auto Fuzzer")
    parser.add_argument("interface", help="Network interface (e.g. eth0)")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between fuzz sends in seconds (default 2s)")
    args = parser.parse_args()

    fields = ["system-name", "system-description", "custom"]
    payloads = [
        b"https://phish.local",
        b"A" * 1000,
        b"TestDevice",
        b"\x00\xff\xfe\x01\x02",  # binary garbage example
        b"NormalPayload123"
    ]

    print(f"[=] Starting automatic LLDP fuzzing on {args.interface} with {args.delay}s delay")

    try:
        for field in fields:
            for payload in payloads:
                print(f"\n[~] Fuzzing field '{field}' with payload length {len(payload)}")
                send_lldp(args.interface, field, payload)
                time.sleep(args.delay)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
        sys.exit(0)

