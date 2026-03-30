import unittest
import struct
import SimpleTor_cell as stc


class SimpleTorStructTest(unittest.TestCase):
    
    def test_Padding(self):
        circID = 1
        cmd = stc.CellCmd.RELAY
        payload = b'Test payload for padding'

        cell = stc.pack_cell(circID, cmd, payload)
        
        self.assertEqual(len(cell), stc.CELL_LEN,"Cell length is not equal to 512")

    def test_unpack_cell(self):
        circID = 1
        cmd = stc.CellCmd.RELAY
        payload = b'Test payload for padding'

        padding = b'\x00' * (stc.CELL_BODY_LEN - len(payload))
        padded_payload = payload + padding

        cell = stc.pack_cell(circID, cmd, padded_payload)
        new_circID, new_cmd, new_payload = stc.unpack_cell(cell)


        self.assertEqual(new_circID,circID, "Circuit ID is not matched")
        self.assertEqual(new_cmd,cmd, "Cell command is not matched")
        self.assertEqual(new_payload,padded_payload, "Payload is not matched")
        
        


if __name__ == '__main__':
    unittest.main()