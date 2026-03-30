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

        packed_relay_cell = stc.pack_relayCell(relayCmd, streamID,data)
        print(packed_relay_cell)
        self.assertEqual(len(packed_relay_cell), 509, "Relay Cell length is not equal to 509")
        
        expected_relay_cell = b'\x02\x00\x00\x00\x02\x00\x00\x00\x00\x23' + data + b'\x00' * (stc.RELAY_CELL_LEN - 11-35)
        self.assertEqual(expected_relay_cell, packed_relay_cell, "Value of relay cell is unexpected")
if __name__ == '__main__':
    unittest.main()