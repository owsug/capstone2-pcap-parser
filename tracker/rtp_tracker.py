from collections import defaultdict

class RTPStreamTracker:
    def __init__(self):
        self.streams = defaultdict(list)  # key = (ssrc, src_ip, dst_ip, dst_port)
        self.allowed_endpoints = set()  # (ip, port)

    def set_allowed_endpoints(self, allowed_set: set[tuple[str, int]]):
        self.allowed_endpoints = allowed_set

    def feed_packet(self, packet_index, timestamp, ip_src, ip_dst, rtp_header, dst_port):
        ssrc = rtp_header["ssrc"]
        key = (ssrc, ip_src, ip_dst, dst_port)
        self.streams[key].append({
            "index": packet_index,
            "timestamp": float(timestamp),
            "seq": rtp_header["sequence_number"],
            "ts": rtp_header["timestamp"],
            "pt": rtp_header["payload_type"],
        })
    
    def _analyze_stream(self, packets):
        def seq_diff(current, previous):
            # RTP sequence number is 16-bit (wraps at 65536)
            return (current - previous + 65536) % 65536

        if len(packets) < 2:
            return {
                "packet_loss": 0,
                "loss_rate": 0.0,
                "avg_jitter": 0.0,
                "max_jitter": 0.0,
            }

        # Sort packets by sequence number with wraparound in mind
        sorted_packets = sorted(packets, key=lambda p: p["seq"])
        seqs = [p["seq"] for p in sorted_packets]
        timestamps = [float(p["timestamp"]) for p in sorted_packets]

        # Estimate total expected packets with wraparound
        expected = seq_diff(seqs[-1], seqs[0]) + 1
        received = len(seqs)
        lost = expected - received if expected > received else 0

        # Calculate jitter (difference between arrival interval and RTP timestamp interval)
        jitters = []
        for i in range(1, len(sorted_packets)):
            delta_arrival = (timestamps[i] - timestamps[i - 1]) * 1000  # ms
            delta_rtp = (sorted_packets[i]["ts"] - sorted_packets[i - 1]["ts"]) / 8  # 8kHz = 125us/sample
            d = abs(delta_arrival - delta_rtp)
            jitters.append(d)

        avg_jitter = sum(jitters) / len(jitters) if jitters else 0.0
        max_jitter = max(jitters) if jitters else 0.0

        return {
            "packet_loss": lost,
            "loss_rate": round(lost / expected * 100, 2) if expected else 0.0,
            "avg_jitter": round(avg_jitter, 2),
            "max_jitter": round(max_jitter, 2),
        }



    def print_summary(self):
        print("\n=== RTP Streams ===")
        for key in self.streams.keys():
            print("SSRC in tracker:", key)
        if not self.streams:
            print("No RTP streams detected.")
            return

        # Group by (src, dst, port) pair (ignoring SSRC)
        grouped = defaultdict(list)  # key = frozenset({src, dst, port})

        for (ssrc, ip_src, ip_dst, port), packets in self.streams.items():
            # Use bidirectional key
            key = frozenset([(ip_src, port), (ip_dst, port)])
            grouped[key].append((ssrc, ip_src, ip_dst, port, packets))

        for key, ssrc_streams in grouped.items():
            print("\n--- RTP Flow Group ---")
            for ssrc, ip_src, ip_dst, dst_port, packets in ssrc_streams:
                print(f"\n🎪 SSRC: {ssrc:08x} ({len(packets)} packets)")
                print(f"    ↳ {ip_src} → {ip_dst}:{dst_port}")
                for pkt in packets[:5]:
                    print(f"  [{pkt['timestamp']}] #{pkt['index']} : Seq={pkt['seq']} TS={pkt['ts']} PT={pkt['pt']}")

                # Quality analysis
                quality = self._analyze_stream(packets)
                print("📊 RTP 품질 분석 결과:")
                print(f"  - 📉 패킷 손실 수: {quality['packet_loss']}")
                print(f"  - 🔻 손실률: {quality['loss_rate']}%")
                print(f"  - 🌀 평균 지터: {quality['avg_jitter']} ms")
                print(f"  - 🚨 최대 지터: {quality['max_jitter']} ms")