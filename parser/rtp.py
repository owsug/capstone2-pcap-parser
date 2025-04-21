import struct

def is_rtp_packet(data: bytes) -> bool:
    """
    Check if the given UDP payload is an RTP packet.

    Basic RTP structure:
      - Minimum length: 12 bytes
      - First byte's top 2 bits: Version (must be 2)
      - Second byte's lower 7 bits: Payload Type

    Common RTCP payload types (not RTP):
      - 72: Sender Report (SR)
      - 73: Receiver Report (RR)
      - 74: Source Description (SDES)
      - 75: Goodbye (BYE)
      - 76: Application-defined (APP)

    These types resemble RTP but are RTCP, so we filter them out.

    """
    if len(data) < 12:
        return False

    b0, b1 = data[0], data[1]
    version = b0 >> 6
    payload_type = b1 & 0x7F  # lower 7 bits

    if version != 2:
        return False

    # Filter out known RTCP payload types
    if payload_type in {72, 73, 74, 75, 76}:
        return False

    return True


def is_rtcp_packet(data: bytes) -> bool:
    if len(data) < 8:
        return False

    version = data[0] >> 6
    pt = data[1] & 0x7F

    return version == 2 and pt in {72, 73, 74, 75, 76}


def parse_rtp_header(data: bytes) -> dict | None:
    """
    Parse RTP header fields from the given data.

    According to RFC 3550, the RTP header has a minimum length of 12 bytes and contains:
      0               1               2               3
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |V=2|P|X|  CC   |M|     PT      |       sequence number         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           timestamp                           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |           synchronization source (SSRC) identifier            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """
    if len(data) < 12:
        return None

    b0, b1 = data[0], data[1]
    version = b0 >> 6
    if version != 2:
        return None

    payload_type = b1 & 0x7F
    sequence_number, = struct.unpack("!H", data[2:4])
    timestamp, = struct.unpack("!I", data[4:8])
    ssrc, = struct.unpack("!I", data[8:12])

    return {
        "version": version,
        "sequence_number": sequence_number,
        "timestamp": timestamp,
        "ssrc": ssrc,
        "payload_type": payload_type,
    }
