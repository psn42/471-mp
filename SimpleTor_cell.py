import struct
from enum import IntEnum
import hashlib
import SimpleTor_crypto_utils as crypto
import hmac
#length of parameters for Circuit cell

CELL_LEN = 512
CIRCID_ID_LEN = 2
CELL_CMD_LEN = 1
CELL_BODY_LEN = 509

#length of parameters for Relay cell

RELAY_CELL_LEN = 509 
RELAY_CELL_CMD_LEN = 1 
RELAY_CELL_RECOGNIZED_LEN = 2
RELAY_CELL_STREAM_ID_LEN = 2
RELAY_CELL_DIGEST_LEN = 4
RELAY_CELL_LENGTH_LEN = 2
RELAY_CELL_DATA_LEN = 498


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
    assert 0 <= circID <= 65535, "pack_cell(): Unexpected Length of Circuit ID"
    assert 0 <= cellCmd <= 255, "pack_cell(): Unexpected Length of Circuit Command"
    assert len(payload) <= CELL_BODY_LEN, "pack_cell(): Length of payload exceeded"
    try:
        padding = b'\x00' * (CELL_BODY_LEN - len(payload))
        padded_payload = payload + padding
        packed_cell = struct.pack('>HB509s', circID, cellCmd, padded_payload)
    except Exception as e:
        print(f"Unexpected Error when packing Circuit Cell: {e}")

    #assert len(packed_cell) == CELL_LEN, "pack_cell(): Unexpected length of Circuit Cell." 
    return packed_cell

def unpack_cell(in_cell : bytes):
    assert len(in_cell) == CELL_LEN, "unpack_cell(): Unexpected Length of Cell"
    try:
        circID, cellCmd, payload = struct.unpack('>HB509s', in_cell)
    except Exception as e:
        print(f"Unexpected Error when unpacking Circuit Cell: {e}")

    return circID, cellCmd, payload


# def pack_relayCell(relayCmd :int, streamID : int, data : bytes) -> bytes:
#     data_len = len(data)
#     assert 0 <= relayCmd <= 255, "pack_relayCell(): Unexpected Length of Relay ID"
#     assert 0 <= streamID <= 65535, "pack_relayCell(): Unexpected Length of stream ID"
#     assert data_len <= RELAY_CELL_DATA_LEN, "pack_relayCell(): Unexpected Length of Data"

    try:
        padding = b'\x00' * (RELAY_CELL_DATA_LEN - data_len)
        recognized = 0
        padded_data = data + padding
        dummy_digest = b'\x00\x00\x00\x00'
        packed_relay_cell = struct.pack('>BHH4sH498s', relayCmd, recognized, streamID, dummy_digest, data_len, padded_data)
        
    except Exception as e:
        print(f"Unexpected Error when packing Relay Cell: {e}")   
       
    return packed_relay_cell


def pack_relayCell_with_digest(relayCmd :int, streamID : int, data : bytes,digest_machine) -> bytes:
    data_len = len(data)
    assert 0 <= relayCmd <= 255, "pack_relayCell(): Unexpected Length of Relay ID"
    assert 0 <= streamID <= 65535, "pack_relayCell(): Unexpected Length of stream ID"
    assert data_len <= RELAY_CELL_DATA_LEN, "pack_relayCell(): Unexpected Length of Data"

    try:
        padding = b'\x00' * (RELAY_CELL_DATA_LEN - data_len)
        recognized = 0
        padded_data = data + padding
        dummy_digest = b'\x00\x00\x00\x00'
        predigest_relay_cell = struct.pack('>BHH4sH498s', relayCmd, recognized, streamID, dummy_digest, data_len, padded_data)
        digest_machine.update(predigest_relay_cell)
        digest = digest_machine.copy().digest()[:4]
        postdigest_relay_cell = struct.pack('>BHH4sH498s', relayCmd, recognized, streamID, digest, data_len, padded_data)
        return postdigest_relay_cell
        
    except Exception as e:
        print(f"Unexpected Error when packing Relay Cell: {e}")   
    

def unpack_relay_cell(in_cell : bytes):
    assert len(in_cell) == RELAY_CELL_LEN, "unpack_relay_cell(): Unexpected Relay Cell Length"
    try:
        relayCmd, recognized, streamID, digest, data_len, data = struct.unpack('>BHH4sH498s', in_cell)
    except Exception as e:
        print(f"Unexpected Error When Unpacking Relay Cell: {e}")
        
    return relayCmd, recognized, streamID, digest, data_len, data

def verify_relay_cell(received_509_bytes: bytes, digest_machine) -> bool:
    received_digest = received_509_bytes[5:9]
    zeroed_cell = received_509_bytes[:5] + b'\x00\x00\x00\x00' + received_509_bytes[9:]
    digest_machine.update(zeroed_cell)
    expected_digest = digest_machine.copy().digest()[:4]
        
    return hmac.compare_digest(expected_digest, received_digest)


    
        


        
        
    







