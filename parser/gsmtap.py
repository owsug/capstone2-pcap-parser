from enum import IntEnum


class GSMTAPType(IntEnum):
    UM = 0x01
    ABIS = 0x02
    UM_BURST = 0x03
    SIM = 0x04
    GB_LLC = 0x08
    GB_SNDCP = 0x09
    UMTS_RRC = 0x0c
    LTE_RRC = 0x0d
    LTE_MAC = 0x0e
    LTE_MAC_FRAMED = 0x0f
    OSMOCORE_LOG = 0x10
    QC_DIAG = 0x11
    LTE_NAS = 0x12


def get_gsmtap_type_name(value: int) -> str:
    try:
        return GSMTAPType(value).name.replace("_", " ")
    except ValueError:
        return f"Unknown (0x{value:02x})"
