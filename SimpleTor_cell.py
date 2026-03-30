import struct
from enum import IntEnum

CELL_LEN = 512
CIRCID_ID_LEN = 2
CELL_CMD_LEN = 1
CELL_BODY_LEN = 509

class CellCmd(IntEnum):
    PADDING = 0
    CREATE = 1
    CREATED = 2
    RELAY = 3
    DESTROY = 4
    
class RelayCmd(IntEnum):
    BEGIN = 1
    DATA = 2
    END = 3
    CONNECTED = 4
    SENDME = 5
    EXTEND = 6
    EXTENDED = 7

def pack_cell(circID : int, cellCmd : int, payload: bytes) -> bytes:
    assert circID.bit_length != 16, "Unexpected Length of Circuit ID."
    assert cellCmd.bit_length != 8, "Unexpected Length of Circuit ID."
    assert len(payload) <= CELL_BODY_LEN, "Length of payload exceeded"
    
    padding = b'\x00' * (CELL_BODY_LEN - len(payload))
    
    
    padded_payload = payload + padding
    assert padded_payload
    packed_cell = struct.pack('>HB509s', circID, cellCmd, padded_payload)
    return packed_cell

def unpack_cell(in_cell : bytes):
    assert len(in_cell) == CELL_LEN, "Unexpected Length of Cell"

    circID, cellCmd, payload = struct.unpack('>HB509s', in_cell)
    return circID, cellCmd, payload





