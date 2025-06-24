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

device_signatures = {
    'cisco': {
        'system-name': ['Cisco', 'Catalyst', 'IOS'],
        'system-description': ['Cisco IOS Software', 'Cisco Systems'],
        'oui': ['00:0c:29', '00:1b:54', '00:1e:49'],
    },
    'juniper': {
        'system-name': ['Juniper'],
        'system-description': ['Juniper Networks'],
        'oui': ['00:05:85', '00:1c:73'],
    },
    'paloalto': {
        'system-name': ['PA-', 'PaloAlto'],
        'system-description': ['Palo Alto Networks'],
        'oui': ['00:0c:29'],
    }
}

# Mapa OUI → Vendor
oui_map = {
    "00:0c:29": "VMware / PaloAlto (virtual)",
    "00:1b:54": "Cisco",
    "00:1e:49": "Cisco",
    "00:05:85": "Juniper",
    "00:1c:73": "Juniper",
    "00:1a:8c": "HPE",
    "dc:9f:db": "Ubiquiti",
    "00:50:56": "VMware",
    "b0:6e:bf": "Aruba",
}

def decode_capabilities(bits):
    return " + ".join(name for bit, name in CAPABILITY_NAMES if bits & (1 << bit)) or "None"

def match_vendor(system_name, system_description, chassis_mac):
    system_name = system_name.lower() if system_name else ""
    system_description = system_description.lower() if system_description else ""
    oui = chassis_mac.lower()[0:8] if chassis_mac else ""

    for vendor, patterns in device_signatures.items():
        if any(pat.lower() in system_name for pat in patterns.get('system-name', [])):
            return vendor
        if any(pat.lower() in system_description for pat in patterns.get('system-description', [])):
            return vendor
        if any(oui.startswith(oui_pat) for oui_pat in patterns.get('oui', [])):
            return vendor
    return None

def parse_lldpdu(payload):
    idx = 0
    seen = set()

    chassis_mac = None
    system_name = None
    system_description = None

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
        seen.add(tlv_type)

        if tlv_type == 1:
            subtype = value[0]
            data = value[1:]
            subtype_str = {
                1: "Chassis MAC",
                2: "Interface name",
                4: "Local"
            }.get(subtype, f"Subtype {subtype}")
            try:
                output_str = data.decode("utf-8")
                if not output_str.strip():
                    raise ValueError
            except:
                output_str = data.hex(":")
            print(f"📦 Chassis ID ({subtype_str}): {output_str}")
            if subtype == 1:
                chassis_mac = output_str

        elif tlv_type == 2:
            subtype = value[0]
            data = value[1:]
            subtype_str = {
                3: "MAC address",
                5: "Interface name",
                7: "Local"
            }.get(subtype, f"Subtype {subtype}")
            output = data.hex(":") if subtype == 3 else data.decode(errors='ignore')
            print(f"🔌 Port ID ({subtype_str}): {output}")

        elif tlv_type == 3:
            ttl = struct.unpack("!H", value)[0]
            print(f"⏳ Time to Live: {ttl} sec")

        elif tlv_type == 4:
            print(f"📘 Port Description: {value.decode(errors='ignore')}")

        elif tlv_type == 5:
            decoded = value.decode(errors='ignore')
            print(f"🖥 System Name: {decoded}  ← peer hostname")
            system_name = decoded

        elif tlv_type == 6:
            decoded = value.decode(errors='ignore')
            print(f"📝 System Description: {decoded}  ← peer OS or platform")
            system_description = decoded

        elif tlv_type == 7:
            if len(value) >= 4:
                sys_caps, enabled_caps = struct.unpack("!HH", value[:4])
                print(f"📡 System Capabilities: {decode_capabilities(sys_caps)} (0x{sys_caps:04x})")
                print(f"🟢 Enabled Capabilities: {decode_capabilities(enabled_caps)} (0x{enabled_caps:04x})")
            else:
                print("⚠ System Capabilities: malformed")

        elif tlv_type == 8:
            mgmt_addr_len = value[0]
            mgmt_addr = value[1:1+mgmt_addr_len]
            addr_str = ".".join(str(b) for b in mgmt_addr) if mgmt_addr_len == 4 else mgmt_addr.hex()
            print(f"🛠 Management Address: {addr_str}")

        elif tlv_type == 0:
            print("✅ End of LLDPDU")

        else:
            print(f"🧩 {desc}: {value.hex()}")

    for required in [1, 2, 3, 4, 5, 6, 7, 8]:
        if required not in seen:
            label = TLV_TYPE_MAP.get(required, f"TLV {required}")
            print(f"⚠ {label}: [brak]")

    vendor = match_vendor(system_name, system_description, chassis_mac)
    if vendor:
        print(f"🔍 Detected vendor: {vendor.upper()}")

def handle_packet(pkt):
    if Ether in pkt and pkt.type == LLDP_ETHERTYPE:
        eth = pkt[Ether]
        print(f"\n📥 LLDP packet received from {eth.src}")
        oui_prefix = eth.src.lower()[0:8]
        vendor_from_oui = oui_map.get(oui_prefix)
        if vendor_from_oui:
            print(f"🔍 MAC OUI vendor: {vendor_from_oui}")
        if Raw in pkt:
            payload = pkt[Raw].load
            parse_lldpdu(payload)

print("🔎 Sniffing LLDP frames (press Ctrl+C to stop)...\n")
sniff(filter="ether proto 0x88cc", prn=handle_packet, store=0, iface="eth0")

