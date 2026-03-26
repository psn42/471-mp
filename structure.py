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
    assert circID.bit_length <= 16, "Length of Circuit ID exceeded" 


