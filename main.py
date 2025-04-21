"""
Parse pcap file captured by SCAT.

SCAT sends packets to 127.0.0.1:
  - Control plane → UDP port 4729 (encapsulated with GSMTAP)
  - User plane    → UDP port 47290 (encapsulated raw IP, often IPv6)

For reference: https://github.com/fgsect/scat

Each SCAT packet in PCAP is wrapped like this:

====================== Ethernet Header (14 bytes) ======================

Byte Offset | Field       | Length | Value (example)    | Description
------------+-------------+--------+--------------------+--------------------------
0x00        | Dest MAC    | 6      | 00:00:00:00:00:00  | Destination MAC address
0x06        | Src MAC     | 6      | 00:00:00:00:00:00  | Source MAC address
0x0C        | EtherType   | 2      | 0x0800             | EtherType (0x0800 = IPv4)

=======================================================================

======================== IPv4 Header (20 bytes) ========================

Byte Offset | Field             | Length | Value (example) | Description
------------+-------------------+--------+------------------+------------------------------------------
0x00        | Version & IHL     | 1      | 0x45             | Version (4 bits) + IHL = 5 (4 bytes each)
0x01        | DSCP & ECN        | 1      | 0x00             | Type of Service
0x02        | Total Length      | 2      | 0x0040           | Total length of IP packet (header + data)
0x04        | Identification    | 2      | 0x1c46           | Unique packet ID
0x06        | Flags & Frag Off  | 2      | 0x4000           | Flags (3 bits) + Fragment Offset
0x08        | TTL               | 1      | 0x40             | Time To Live
0x09        | Protocol          | 1      | 0x11             | Protocol (0x11 = UDP)
0x0A        | Header Checksum   | 2      | 0xffff           | Checksum for header validation
0x0C        | Source IP Address | 4      | 127.0.0.1        | Sender IP address
0x10        | Dest IP Address   | 4      | 127.0.0.X        | Receiver IP address (X = radio ID)

========================================================================

========================== UDP Header (8 bytes) ==========================

Byte Offset | Field           | Length | Value (example) | Description
------------+-----------------+--------+------------------+-----------------------------------------
0x00        | Source Port     | 2      | 0x3419 (13337)   | Typically SCAT uses 13337
0x02        | Dest Port       | 2      | 0x1279 or 0xB8BA | 4729 = control plane, 47290 = user plane
0x04        | Length          | 2      | 0x0030           | UDP header + payload length
0x06        | Checksum        | 2      | 0xffff           | Optional, sometimes 0x0000 or placeholder

=========================================================================

=========================== SCAT Payload ============================

Port = 4729 (Control Plane):
    → GSMTAP header + protocol-specific signaling (e.g., LTE RRC, NAS, etc.)
    → GSMTAP format:
        Byte 0: Version = 0x02
        Byte 1: Type    = 0x0D (e.g., LTE_RRC)
        Byte 2: Subtype/Reserved
        Byte 3: Length
        ...

Port = 47290 (User Plane):
    → Raw IP packet (IPv6 or IPv4)
    → Starts with:
        0x60 ... : IPv6 packet (most common)
        0x45 ... : IPv4 packet
    → These will be parsed as normal IP packets, leading to UDP → RTP

=====================================================================


Example bytes:

  Ethernet:
    00 00 00 00 00 00    # Destination MAC
    00 00 00 00 00 00    # Source MAC
    08 00                # EtherType = IPv4

  IPv4:
    45 00                # Version + IHL + DSCP
    00 XX                # Total length
    YY YY                # Identification
    40 00                # Flags, Fragment Offset
    40                   # TTL = 64
    11                   # Protocol = UDP (17)
    FF FF                # Header Checksum
    7F 00 00 01          # Source IP: 127.0.0.1
    7F 00 00 XX          # Destination IP: 127.0.0.X

  UDP:
    34 19                # Source port = 13337
    12 79 or B8 BA       # Destination port = 4729 or 47290
    00 XX                # Length = 8 + payload
    FF FF                # Checksum

  Payload:
    If control plane:
      └─ GSMTAP Header: 02 00 0d 00 …
          (0x0d = LTE RRC)
    If user plane:
      └─ IP Packet:
         - IPv6 (starts with 0x60)
         - or IPv4 (starts with 0x45)
"""

from parser.pcap import PcapParser
from parser.ip import parse_ip_packet
from parser.gsmtap import get_gsmtap_type_name
from tracker.sip_tracker import SipSessionTracker
from parser.rtp import is_rtp_packet, parse_rtp_header
from tracker.rtp_tracker import RTPStreamTracker
from util.decapsulator import decapsulate_and_write_ip_only

PORT_CP = 4729
PORT_UP = 47290

def parse_pcap(filename):
  # sip_tracker = SipSessionTracker()
  # rtp_tracker = RTPStreamTracker()

  packets = list(PcapParser(filename))

  # for index, ts, udp_dst_port, payload in packets:
  #     if udp_dst_port == PORT_CP:
  #         proto = payload[2] if len(payload) > 2 else None
  #         proto_name = get_gsmtap_type_name(proto) if proto is not None else "Invalid"
  #         print(f"[{ts}] Packet #{index} → Control Plane (GSMTAP), {len(payload)} bytes, Protocol: {proto_name}")

  #     elif udp_dst_port == PORT_UP:
  #         result, src_ip, dst_ip, udp_payload, dst_port = parse_ip_packet(payload, return_meta=True)
  #         print(f"[{ts}] Packet #{index} → User Plane, {len(payload)} bytes, {result}")
  #         if udp_payload:
  #             sip_tracker.feed_packet(index, ts, src_ip, dst_ip, udp_payload)

  # rtp_tracker.set_allowed_endpoints(sip_tracker.get_rtp_stream_filter())
  # for index, ts, udp_dst_port, payload in packets:
  #     if udp_dst_port == PORT_UP:
  #         result, src_ip, dst_ip, udp_payload, dst_port = parse_ip_packet(payload, return_meta=True)
  #         if udp_payload and is_rtp_packet(udp_payload):
  #             rtp_info = parse_rtp_header(udp_payload)
  #             if rtp_info:
  #                 rtp_tracker.feed_packet(index, ts, src_ip, dst_ip, rtp_info, dst_port)

  # sip_tracker.print_summary()
  # rtp_tracker.print_summary()

  decapsulate_and_write_ip_only(packets, filename.replace(".pcap", ".clean.pcap"))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.pcap>")
        exit(1)
    parse_pcap(sys.argv[1])