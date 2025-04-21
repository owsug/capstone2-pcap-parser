from scapy.all import PcapWriter, IPv6, IP


def is_ip_packet(data: bytes) -> bool:
    if len(data) < 1:
        return False
    version = data[0] >> 4
    return version in {4, 6}


def extract_scat_payload(raw_payload: bytes) -> bytes | None:
    """
    Extract the actual IP payload from a SCAT-encapsulated UDP packet.
    Assumes Ethernet(14) + IPv4(20) + UDP(8) = 42-byte prefix.
    """
    if len(raw_payload) < 42:
        return None
    return raw_payload[42:]

def extract_gsmtap_payload(data: bytes) -> tuple[int, bytes] | None:
    """
    Extract the GSMTAP type and payload from a SCAT-encapsulated
    GSMTAP header needs length least 4 bytes.
    """
    if len(data) < 4:
        return None
    
    gsmtap_type = data[2]  # GSMTAP type is in the second byte
    gsmtap_payload = data[4:]  # Skip the GSMTAP header (4 bytes)
    return gsmtap_type, gsmtap_payload

def decapsulate_and_write_ip_only(packets, output_file):
    writer = PcapWriter(output_file, append=False, sync=True)

    for index, ts, udp_dst_port, payload in packets:
        if udp_dst_port != 47290:
            continue

        # Check if payload is IPv6 or IPv4 and long enough
        if len(payload) >= 1:
            version = payload[0] >> 4
            if version == 6 and len(payload) >= 40:
                try:
                    pkt = IPv6(payload)
                    pkt.time = float(ts)
                    writer.write(pkt)
                except Exception as e:
                    print(f"[!] Failed to decode IPv6 packet #{index}: {e}")
            elif version == 4 and len(payload) >= 20:
                try:
                    pkt = IP(payload)
                    pkt.time = float(ts)
                    writer.write(pkt)
                except Exception as e:
                    print(f"[!] Failed to decode IPv4 packet #{index}: {e}")
            else:
                print(f"[!] Skipped unknown or malformed IP packet #{index} (len={len(payload)})")


# TODO:
#    - extract GSMTAP header and decapsulate the payload
#    - extract RRC header and decapsulate the payload
