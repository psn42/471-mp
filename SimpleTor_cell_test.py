import unittest
import struct
import SimpleTor_cell as stc


class SimpleTorStructTest(unittest.TestCase):
    
    def test_pack_cell(self):
        circID = 1
        cmd = stc.CellCmd.RELAY
        payload = b'Test payload for padding'

        cell = stc.pack_cell(circID, cmd, payload)
        
        self.assertEqual(len(cell), stc.CELL_LEN,"Cell length is not equal to 512")
        
        expected_cell = b'\x00\x01\x03' + payload + b'\x00' * (512-27)
        self.assertEqual(expected_cell,cell, "Unexpected Cell value")

    def test_unpack_cell(self):
        circID = 1
        cmd = stc.CellCmd.RELAY
        payload = b'Test payload for Circuit Cell packing'

        padding = b'\x00' * (stc.CELL_BODY_LEN - len(payload))
        padded_payload = payload + padding

        cell = stc.pack_cell(circID, cmd, padded_payload)
        new_circID, new_cmd, new_payload = stc.unpack_cell(cell)


        self.assertEqual(new_circID,circID, "Circuit ID is not matched")
        self.assertEqual(new_cmd,cmd, "Cell command is not matched")
        self.assertEqual(new_payload,padded_payload, "Payload is not matched")
        
        
    def test_pack_relay_cell(self):
        relayCmd = stc.RelayCmd.DATA
        streamID = 2
        data = b'Test payload for Relay Cell packing'
        data_len = len(data)
        packed_relay_cell = stc.pack_relayCell(relayCmd, streamID,data)
        self.assertEqual(len(packed_relay_cell), 509, "Relay Cell length is not equal to 509")
        
        expected_relay_cell = b'\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x23' + data + (b'\x00' * (stc.RELAY_CELL_DATA_LEN - data_len))

        self.assertEqual(expected_relay_cell, packed_relay_cell, "Value of relay cell is unexpected")
        
    def test_unpack_relay_cell(self):
        relayCmd = stc.RelayCmd.DATA
        streamID = 2
        data = b'Test payload for Relay Cell unpacking' #37 length
        data_len = len(data)
        packed_relay_cell = stc.pack_relayCell(relayCmd, streamID,data)
        new_relayCmd, new_recognized, new_streamID, new_digest, new_data_len, new_data = stc.unpack_relay_cell(packed_relay_cell)
        
        self.assertEqual(new_relayCmd,relayCmd, "Relay Command is not matched")
        self.assertEqual(new_recognized, 0, "Recognized is not matched")
        self.assertEqual(new_streamID, streamID,"Stream ID is not matched")
        self.assertEqual(new_digest, b'\x00\x00\x00\x00', "Digest is not matched")
        self.assertEqual(new_data_len, data_len, "Data Length is not matched")
        
        expected_data = data + (b'\x00' * (stc.RELAY_CELL_DATA_LEN - data_len))

        self.assertEqual(new_data,expected_data, "Data is not matched")
        
        
        
        
if __name__ == '__main__':
    unittest.main()