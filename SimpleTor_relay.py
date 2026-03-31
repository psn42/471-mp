import socket
import threading
import SimpleTor_cell as stc
import SimpleTor_crypto_utils as crypto

class RelayState:
    def __init__(self):
        self.circuit_table = {}

    def register_circuit(self, circ_id, aes_key, iv, next_hop, next_circ_id=None):
        self.circuit_table[circ_id] = {
            "aes_key": aes_key,
            "iv": iv,
            "next_hop": next_hop,
            "next_circ_id": next_circ_id or circ_id
        }

relay_state = RelayState()

def handle_client(conn, addr, default_next_hop):
    print(f"Accepted connection from {addr}")
    try:
        while True:
            raw_cell = conn.recv(stc.CELL_LEN)
            if not raw_cell:
                break
            if len(raw_cell) != stc.CELL_LEN:
                print(f"Received incomplete cell ({len(raw_cell)} bytes), dropping.")
                continue
            try:
                circID, cellCmd, payload = stc.unpack_cell(raw_cell)
            except Exception as e:
                print(f"Failed to unpack incoming circuit cell: {e}")
                continue
            if cellCmd == stc.CellCmd.CREATE:
                print(f"New Circuit Request: {circID}. Performing ECDH Key Exchange...")
                client_pub_bytes = payload[:32] 
                try:
                    relay_priv_key, relay_pub_bytes = crypto.generate_ecdh_keypair()
                    shared_secret = crypto.compute_shared_secret(relay_priv_key, client_pub_bytes)
                    aes_key, iv = crypto.derive_keys(shared_secret)
                    relay_state.register_circuit(circID, aes_key, iv, default_next_hop)
                    print(f"Cryptographic keys derived and stored for Circuit {circID}")
                    created_cell = stc.pack_cell(circID, stc.CellCmd.CREATED, relay_pub_bytes)
                    conn.sendall(created_cell)
                    print(f"Sent CREATED cell back to {addr}")
                except Exception as e:
                    print(f"Key Exchange Failed: {e}")
                continue
            if cellCmd == stc.CellCmd.RELAY:
                route = relay_state.circuit_table.get(circID)
                if not route:
                    print(f"No route found for circuit {circID}; dropping cell.")
                    continue
                try:
                    decrypted_payload = crypto.onion_decrypt(
                        route["aes_key"], 
                        route["iv"], 
                        payload
                    )
                    
                    relayCmd, recognized, streamID, digest, data_len, data = stc.unpack_relay_cell(decrypted_payload)
                    
                    if recognized == 0:
                        ################################################
                        # Handles inner relay command
                        if not stc.verify_relay_cell(decrypted_payload):
                            print(f"Authentication Failed: Bad Digest for Circuit {circID}. Dropping.")
                            continue
                        print(f"Decrypted and Verified valid cell for Circuit {circID}")
                        if relayCmd == stc.RelayCmd.DATA:
                            actual_message = data[:data_len]
                            print(f"[Exit Node] Successfully extracted Application Data: {actual_message}")
                            
                        elif relayCmd == stc.RelayCmd.EXTEND:
                            print(f"[Relay Node] Received EXTEND command. (Implementation pending)")
                        else:
                            print(f"[Relay Node] Processed relay command: {relayCmd}")
                        continue
                        ################################################
                    else:
                        print(f"Cell recognized != 0. Forwarding to next hop.")

                    next_host, next_port = route["next_hop"]
                    next_circID = route["next_circ_id"]
                    
                    forward_cell = stc.pack_cell(next_circID, stc.CellCmd.RELAY, decrypted_payload)
                    forward_to_next_hop(next_host, next_port, forward_cell)

                except Exception as e:
                    print(f"Cryptographic Error on Circuit {circID}: {e}")

    except ConnectionResetError:
        print(f"Connection with {addr} reset.")
    finally:
        conn.close()

def forward_to_next_hop(host, port, data):
    try:
        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        forward_socket.connect((host, port))
        forward_socket.sendall(data)
        print(f"Forwarded 512-byte cell to {host}:{port}")
        forward_socket.close()
    except Exception as e:
        print(f"Failed to forward data to {host}:{port}: {e}")

def start_relay(host='localhost', port=8001, default_next_host='localhost', default_next_port=8002):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    
    print(f"Relay listening on {host}:{port} (Raw TCP)")

    while True:
        conn, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr, (default_next_host, default_next_port)))
        client_thread.daemon = True
        client_thread.start()

if __name__ == '__main__':
    start_relay()