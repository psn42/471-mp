import socket
import threading
import struct
import secrets
import hmac
import sys
import SimpleTor_cell as stc
import SimpleTor_crypto_utils as crypto

class RelayState:
    def __init__(self):
        self.circuit_table = {}

    def register_forward_route(self, in_sock, in_circ_id, fwd_cipher, bwd_cipher, fwd_digest, bwd_digest):
        self.circuit_table[(in_sock, in_circ_id)] = {
            "is_reverse": False,
            "fwd_cipher": fwd_cipher,
            "bwd_cipher": bwd_cipher,
            "fwd_digest": fwd_digest,
            "bwd_digest": bwd_digest,
            "next_socket": None,
            "next_circ_id": None
        }

    def link_circuits(self, in_sock, in_circ_id, out_sock, out_circ_id):
        if (in_sock, in_circ_id) in self.circuit_table:
            self.circuit_table[(in_sock, in_circ_id)]["next_socket"] = out_sock
            self.circuit_table[(in_sock, in_circ_id)]["next_circ_id"] = out_circ_id
        self.circuit_table[(out_sock, out_circ_id)] = {
            "is_reverse": True,
            "fwd_cipher": self.circuit_table[(in_sock, in_circ_id)]["fwd_cipher"],
            "bwd_cipher": self.circuit_table[(in_sock, in_circ_id)]["bwd_cipher"],
            "fwd_digest": self.circuit_table[(in_sock, in_circ_id)]["fwd_digest"],
            "bwd_digest": self.circuit_table[(in_sock, in_circ_id)]["bwd_digest"],
            "next_socket": in_sock,
            "next_circ_id": in_circ_id
        }

relay_state = RelayState()

def handle_client(conn, addr):
    print(f"Listening to stream from {addr}")
    try:
        while True:
            raw_cell = conn.recv(stc.CELL_LEN)
            if not raw_cell:
                break
            if len(raw_cell) != stc.CELL_LEN:
                continue
                
            try:
                circID, cellCmd, payload = stc.unpack_cell(raw_cell)
            except Exception as e:
                print(f"Unpack error: {e}")
                continue
            if cellCmd == stc.CellCmd.CREATE:
                print(f"Circuit {circID}: Performing CREATE2 Handshake")
                try:
                    htype, hlen = struct.unpack('>HH', payload[:4])
                    if htype != 0x0002: continue
                        
                    client_pub_bytes = payload[4 : 4 + hlen]
                    
                    relay_priv_key, relay_pub_bytes = crypto.generate_ecdh_keypair()
                    shared_secret = crypto.compute_shared_secret(relay_priv_key, client_pub_bytes)
                    fwd_d_key, bwd_d_key, fwd_a_key, bwd_a_key = crypto.derive_tor_keys(shared_secret)
                    fwd_cipher, bwd_cipher = crypto.create_relay_ciphers(fwd_a_key, bwd_a_key)
                    fwd_digest, bwd_digest = crypto.create_running_digests()
                    fwd_digest.update(fwd_d_key)
                    bwd_digest.update(bwd_d_key)
                    relay_state.register_forward_route(conn, circID, fwd_cipher, bwd_cipher, fwd_digest, bwd_digest)
                    
                    created_cell = stc.pack_cell(circID, stc.CellCmd.CREATED, relay_pub_bytes)
                    conn.sendall(created_cell)
                    print(f"Sent CREATED cell backward")
                except Exception as e:
                    print(f"Key Exchange Failed: {e}")
                continue
            if cellCmd == stc.CellCmd.RELAY:
                route = relay_state.circuit_table.get((conn, circID))
                if not route: 
                    print(f"No route for Socket/CircID {circID}")
                    continue
                try:
                    if route.get("is_reverse"):
                        encrypted_payload = route["bwd_cipher"].update(payload)
                        backward_cell = stc.pack_cell(route["next_circ_id"], stc.CellCmd.RELAY, encrypted_payload)
                        route["next_socket"].sendall(backward_cell)
                        continue
                    decrypted_payload = route["fwd_cipher"].update(payload)
                    relayCmd, recognized, streamID, received_digest, data_len, data = stc.unpack_relay_cell(decrypted_payload)
                    if recognized == 0:
                        zeroed_cell = decrypted_payload[:5] + b'\x00\x00\x00\x00' + decrypted_payload[9:]
                        temp_digest = route["fwd_digest"].copy()
                        temp_digest.update(zeroed_cell)
                        expected_digest = temp_digest.finalize()[:4]

                        if hmac.compare_digest(expected_digest, received_digest):
                            route["fwd_digest"].update(zeroed_cell)
                            if relayCmd == stc.RelayCmd.DATA:
                                actual_message = data[:data_len]
                                print(f"[Exit Node] Received Application Data: {actual_message}")
                            elif relayCmd == stc.RelayCmd.EXTEND:
                                ip_bytes, next_port, next_pub_key = struct.unpack('>4sH32s', data[:38])
                                next_ip = socket.inet_ntoa(ip_bytes)
                                print(f"Received EXTEND. Connecting to {next_ip}:{next_port}")

                                next_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                next_socket.connect((next_ip, next_port))
                                next_circ_id = secrets.randbelow(65535) + 1

                                create_payload = struct.pack('>HH32s', 0x0002, 32, next_pub_key)
                                create_cell = stc.pack_cell(next_circ_id, stc.CellCmd.CREATE, create_payload)
                                next_socket.sendall(create_cell)

                                created_resp = next_socket.recv(stc.CELL_LEN)
                                resp_circ_id, resp_cmd, resp_payload = stc.unpack_cell(created_resp)

                                if resp_cmd == stc.CellCmd.CREATED:
                                    relay_reply_pubkey = resp_payload[:32]

                                    relay_state.link_circuits(conn, circID, next_socket, next_circ_id)
                                    threading.Thread(target=handle_client, args=(next_socket, next_ip), daemon=True).start()

                                    padding = b'\x00' * (stc.RELAY_CELL_DATA_LEN - len(relay_reply_pubkey))
                                    padded_data = relay_reply_pubkey + padding
                                    temp_extended = struct.pack('>BHH4sH498s', stc.RelayCmd.EXTENDED, 0, streamID, b'\x00\x00\x00\x00', len(relay_reply_pubkey), padded_data)
                                    
                                    route["bwd_digest"].update(temp_extended)
                                    calculated_digest = route["bwd_digest"].copy().finalize()[:4]
                                    
                                    packed_extended = struct.pack('>BHH4sH498s', stc.RelayCmd.EXTENDED, 0, streamID, calculated_digest, len(relay_reply_pubkey), padded_data)
                                    
                                    encrypted_extended = route["bwd_cipher"].update(packed_extended)
                                    backward_cell = stc.pack_cell(circID, stc.CellCmd.RELAY, encrypted_extended)
                                    
                                    conn.sendall(backward_cell)
                                    print(f"Circuit extended. EXTENDED sent backward.")
                            continue
                    next_sock = route.get("next_socket")
                    if next_sock:
                        forward_cell = stc.pack_cell(route["next_circ_id"], stc.CellCmd.RELAY, decrypted_payload)
                        next_sock.sendall(forward_cell)

                except Exception as e:
                    print(f"Cryptographic/Routing Error: {e}")
                    
    except ConnectionResetError:
        print(f"Connection with {addr} reset.")
    except Exception as e:
        print(f"Stream closed: {e}")
    finally:
        conn.close()

def start_relay(host='0.0.0.0', port=9001):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Relay listening on {host}:{port}")
    while True:
        conn, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.daemon = True
        client_thread.start()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
    start_relay(port=port)