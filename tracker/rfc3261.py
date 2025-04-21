import re

CALL_ID_RE = re.compile(rb'Call-ID:\s*([^\r\n]+)', re.IGNORECASE)
CSEQ_RE = re.compile(rb'CSeq:\s*(\d+)\s+([^\r\n]+)', re.IGNORECASE)
FROM_RE = re.compile(rb'From:\s*(.*)', re.IGNORECASE)
TO_RE = re.compile(rb'To:\s*(.*)', re.IGNORECASE)
VIA_RE = re.compile(rb'Via:\s*(.*)', re.IGNORECASE)
CONTACT_RE = re.compile(rb'Contact:\s*(.*)', re.IGNORECASE)
METHOD_RE = re.compile(rb'^(INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|SIP/2\.0)', re.IGNORECASE | re.MULTILINE)

SDP_RE = re.compile(rb'\r\n\r\n(.*)', re.DOTALL)

def extract_call_id(data: bytes) -> str | None:
    """
    Extracts the Call-ID header from a SIP message.

    Example SIP message:
        INVITE sip:bob@biloxi.com SIP/2.0
        ...
        Call-ID: a84b4c76e66710
    """
    match = CALL_ID_RE.search(data)
    return match.group(1).decode(errors='ignore').strip() if match else None

def extract_method_or_status(data: bytes) -> str:
    """
    Extracts SIP method (INVITE, ACK, BYE...) or status line (SIP/2.0 200 OK).
    """
    match = METHOD_RE.search(data)
    return match.group(1).decode(errors='ignore') if match else "UNKNOWN"

def extract_cseq(data: bytes) -> tuple[str, str] | None:
    """
    Extracts CSeq number and method.

    Example:
        CSeq: 314159 INVITE
        → ('314159', 'INVITE')
    """
    match = CSEQ_RE.search(data)
    if match:
        return match.group(1).decode(), match.group(2).decode()
    return None

def extract_header(data: bytes, header: str) -> str | None:
    """
    Extracts any arbitrary SIP header using its name.

    Example:
        header="From" will match:
        From: "Alice" <sip:alice@atlanta.com>
    """
    regex = re.compile(fr'{header}:\s*(.*)'.encode(), re.IGNORECASE)
    match = regex.search(data)
    return match.group(1).decode(errors='ignore').strip() if match else None

def extract_sdp_fields(data: bytes) -> dict:
    """
    Extracts fields from the SDP body of a SIP message.

    SDP format example:
        v=0
        o=alice 2890844526 2890844526 IN IP4 host.atlanta.com
        s=-
        c=IN IP4 192.0.2.101
        t=0 0
        m=audio 49170 RTP/AVP 0
        a=rtpmap:0 PCMU/8000
        a=fmtp:96 mode-set=1

    SDP fields extracted:
        - media: from 'm=' line
        - connection: from 'c=' line
        - rtpmap: list of codecs
        - fmtp: list of format parameters
    """
    result = {}
    sdp = SDP_RE.search(data)
    if not sdp:
        return result

    sdp_lines = sdp.group(1).split(b'\n')
    for line in sdp_lines:
        line = line.strip()
        if line.startswith(b'm='):
            result['media'] = line[2:].decode(errors='ignore')
        elif line.startswith(b'c='):
            result['connection'] = line[2:].decode(errors='ignore')
        elif line.startswith(b'a=rtpmap:'):
            if 'rtpmap' not in result:
                result['rtpmap'] = []
            result['rtpmap'].append(line[9:].decode(errors='ignore'))
        elif line.startswith(b'a=fmtp:'):
            if 'fmtp' not in result:
                result['fmtp'] = []
            result['fmtp'].append(line[7:].decode(errors='ignore'))

    return result
