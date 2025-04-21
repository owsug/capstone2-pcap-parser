import struct
import ipaddress
import re

CALL_ID_RE = re.compile(rb'Call-ID:\s*([^\r\n]+)', re.IGNORECASE)

def extract_sip_call_id(data: bytes) -> str | None:
    match = CALL_ID_RE.search(data)
    if match:
        return match.group(1).decode(errors='ignore').strip()
    return None

def parse_ipv4(payload: bytes, return_meta=False):
    """
    Parse an IPv4 packet.

    IPv4 header format (RFC 791):
     0                   1                   2                   3  
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |       Header Checksum         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    - Protocol field: 17 = UDP
    """
    if len(payload) < 20:
        return "Invalid IPv4" if not return_meta else ("Invalid IPv4", None, None, None, None)

    ihl = payload[0] & 0x0F
    ip_header_len = ihl * 4
    proto = payload[9]
    src = ipaddress.IPv4Address(payload[12:16])
    dst = ipaddress.IPv4Address(payload[16:20])
    result = f"IPv4: {src} → {dst}, Proto={proto}"

    udp_payload = None
    dst_port = None

    if proto == 17 and len(payload) >= ip_header_len + 8:
        udp_header = payload[ip_header_len:ip_header_len + 8]
        dst_port = struct.unpack('!H', udp_header[2:4])[0]
        udp_payload = payload[ip_header_len + 8:]
        result += f", UDP payload={len(udp_payload)} bytes"

        call_id = extract_sip_call_id(udp_payload)
        if call_id:
            result += f", SIP Call-ID: {call_id}"

    return (result, str(src), str(dst), udp_payload, dst_port) if return_meta else result

def parse_ipv6(payload: bytes, return_meta=False):
    """
    Parse an IPv6 packet.

    IPv6 header format (RFC 8200):
     0                   1                   2                   3  
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version| Traffic Class |           Flow Label                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Payload Length        |  Next Header  |   Hop Limit   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Source Address                        |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Destination Address                      |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    - Next Header field: 17 = UDP
    """
    if len(payload) < 40:
        return "Invalid IPv6" if not return_meta else ("Invalid IPv6", None, None, None, None)

    next_hdr = payload[6]
    src = ipaddress.IPv6Address(payload[8:24])
    dst = ipaddress.IPv6Address(payload[24:40])
    result = f"IPv6: {src} → {dst}, NextHdr={next_hdr}"

    udp_payload = None
    dst_port = None

    if next_hdr == 17 and len(payload) >= 48:
        udp_header = payload[40:48]
        dst_port = struct.unpack('!H', udp_header[2:4])[0]
        udp_payload = payload[48:]
        result += f", UDP payload={len(udp_payload)} bytes"

        call_id = extract_sip_call_id(udp_payload)
        if call_id:
            result += f", SIP Call-ID: {call_id}"

    return (result, str(src), str(dst), udp_payload, dst_port) if return_meta else result

def parse_ip_packet(payload: bytes, return_meta=False):
    """
    Parse IP packet (either IPv4 or IPv6).

    Returns metadata or summary string depending on return_meta.
    """
    if len(payload) < 1:
        return "Empty payload" if not return_meta else ("Empty payload", None, None, None, None)

    version = payload[0] >> 4
    if version == 6:
        return parse_ipv6(payload, return_meta)
    elif version == 4:
        return parse_ipv4(payload, return_meta)
    else:
        return (f"Unknown IP version: {version}", None, None, None, None) if return_meta else f"Unknown IP version: {version}"
