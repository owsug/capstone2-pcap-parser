import struct

ETHERNET_LEN = 14
IPV4_LEN = 20
UDP_LEN = 8
HEADER_TOTAL_LEN = ETHERNET_LEN + IPV4_LEN + UDP_LEN

class PcapParser:
    def __init__(self, filename):
        self.filename = filename

    def __iter__(self):
        with open(self.filename, 'rb') as f:
            f.read(24)  # skip global header
            index = 0
            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, _ = struct.unpack('<LLLL', pkt_hdr)
                pkt_data = f.read(incl_len)

                if len(pkt_data) < ETHERNET_LEN + IPV4_LEN:
                    continue  # too short for even Ethernet + IP

                # Safe guard: UDP header might be truncated
                udp_offset = ETHERNET_LEN + IPV4_LEN
                if len(pkt_data) < udp_offset + 4:
                    print(f"[!] Skipping truncated packet #{index}")
                    continue

                ts = f"{ts_sec}.{str(ts_usec).zfill(6)}"
                udp_dst_port = struct.unpack('!H', pkt_data[udp_offset + 2:udp_offset + 4])[0]
                payload = pkt_data[HEADER_TOTAL_LEN:] if len(pkt_data) >= HEADER_TOTAL_LEN else b''

                yield index, ts, udp_dst_port, payload
                index += 1
