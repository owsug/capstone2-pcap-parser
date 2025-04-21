from collections import defaultdict
from tracker.rfc3261 import (
    extract_call_id,
    extract_method_or_status,
    extract_cseq,
    extract_header,
    extract_sdp_fields,
)

class SipSessionTracker:
    def __init__(self):
        self.sessions = defaultdict(list)
        self.valid_rtp_streams = set()  # (ip, port)

    def feed_packet(self, packet_index, timestamp, ip_src, ip_dst, udp_payload):
        call_id = extract_call_id(udp_payload)
        if not call_id:
            return

        method = extract_method_or_status(udp_payload)
        sdp = extract_sdp_fields(udp_payload)

        if sdp:
            ip = sdp.get("connection", "")
            if ip.startswith("IN IP4 ") or ip.startswith("IN IP6 "):
                ip = ip.split()[-1]
            port = int(sdp.get("media", "").split()[1])

            self.valid_rtp_streams.add((ip_src, port))
            self.valid_rtp_streams.add((ip_dst, port))


        self.sessions[call_id].append({
            "index": packet_index,
            "timestamp": timestamp,
            "src": ip_src,
            "dst": ip_dst,
            "method": method,
            "sdp": sdp or None,
        })

    def get_rtp_stream_filter(self):
        print(">> RTP filter endpoints:")
        for ip, port in self.valid_rtp_streams:
            print(f"   - {ip}:{port}")
        return self.valid_rtp_streams

    def print_summary(self):
        print("\n=== SIP Sessions ===")
        for call_id, messages in self.sessions.items():
            print(f"\n📞 Call-ID: {call_id}")
            for msg in messages:
                print(f"  [{msg['timestamp']}] #{msg['index']} {msg['src']} → {msg['dst']} : {msg['method']}")
                if msg.get("sdp"):
                    print(f"    ↳ SDP: {msg['sdp'].get('media', '')} / {msg['sdp'].get('connection', '')}")
