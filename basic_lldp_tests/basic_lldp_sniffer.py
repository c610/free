#!/usr/bin/env python3

from scapy.all import sniff, Ether, Raw
import struct

LLDP_MULTICAST_MAC = "01:80:c2:00:00:0e"
LLDP_ETHERTYPE = 0x88cc

TLV_TYPE_MAP = {
    0: "End of LLDPDU",
    1: "Chassis ID",
    2: "Port ID",
    3: "Time to Live",
    4: "Port Description",
    5: "System Name",
    6: "System Description",
    7: "System Capabilities",
    8: "Management Address"
}

CAPABILITY_NAMES = [
    (0, "Other"),
    (1, "Repeater"),
    (2, "Bridge"),
    (3, "WLAN Access Point"),
    (4, "Router"),
    (5, "Telephone"),
    (6, "DOCSIS Cable Device"),
    (7, "Station Only"),
    (8, "C-VLAN Component"),
    (9, "S-VLAN Component"),
    (10, "Two-port MAC Relay")
]

def decode_capabilities(bits):
    return " + ".join(name for bit, name in CAPABILITY_NAMES if bits & (1 << bit)) or "None"

def parse_lldpdu(payload):
    idx = 0
    while idx + 2 <= len(payload):
        tlv_header = struct.unpack("!H", payload[idx:idx+2])[0]
        tlv_type = (tlv_header >> 9) & 0x7F
        tlv_len = tlv_header & 0x1FF
        idx += 2

        if tlv_len == 0 or idx + tlv_len > len(payload):
            break

        value = payload[idx:idx+tlv_len]
        idx += tlv_len

        desc = TLV_TYPE_MAP.get(tlv_type, f"Unknown TLV ({tlv_type})")

        if tlv_type == 1:  # Chassis ID
            subtype = value[0]
            data = value[1:]
            print(f"📦 Chassis ID (subtype {subtype}): {data.hex(':')}")
        elif tlv_type == 2:  # Port ID
            subtype = value[0]
            data = value[1:]
            print(f"🔌 Port ID (subtype {subtype}): {data.decode(errors='ignore')}")
        elif tlv_type == 3:  # TTL
            ttl = struct.unpack("!H", value)[0]
            print(f"⏳ Time to Live: {ttl} sec")
        elif tlv_type == 5:  # System Name
            print(f"🖥 System Name: {value.decode(errors='ignore')}")
        elif tlv_type == 6:  # System Description
            print(f"📝 System Description: {value.decode(errors='ignore')}")
        elif tlv_type == 7:  # System Capabilities
            if len(value) >= 4:
                sys_caps, enabled_caps = struct.unpack("!HH", value[:4])
                print(f"📡 System Capabilities: {decode_capabilities(sys_caps)} (0x{sys_caps:04x})")
                print(f"🟢 Enabled Capabilities: {decode_capabilities(enabled_caps)} (0x{enabled_caps:04x})")
            else:
                print("⚠ System Capabilities: malformed")
        elif tlv_type == 0:
            print("✅ End of LLDPDU")
            break
        else:
            print(f"🧩 {desc}: {value.hex()}")

def handle_packet(pkt):
    if Ether in pkt and pkt.type == LLDP_ETHERTYPE:
        eth = pkt[Ether]
        print(f"\n📥 LLDP packet received from {eth.src}")
        if Raw in pkt:
            payload = pkt[Raw].load
            parse_lldpdu(payload)

print("🔎 Sniffing LLDP frames (press Ctrl+C to stop)...\n")
#sniff(filter="ether proto 0x88cc", prn=handle_packet, store=0)
sniff(filter="ether proto 0x88cc", prn=handle_packet, store=0, iface="eth0")

