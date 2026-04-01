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
        "IP": "1.2.3.1",         
        "port": 1234,              
        "flags": ["Guard", "Middle"], 
        "pubkey": "a1b2c3d4e5f6..." 
    },

    "Node2": {
        "IP": "1.2.3.2",
        "port": 1234,
        "flags": ["Middle","Exit"],
        "pubkey": "f6e5d4c3b2a1..."
    },

    "Node3": {
        "IP": "1.2.3.3",
        "port": 1234,
        "flags": ["Guard","Exit"],         
        "pubkey": "112233445566..."
    },

      "Node4": {
        "IP": "1.2.3.4",
        "port": 1234,
        "flags": ["Middle","Guard"],         
        "pubkey": "1241245512555..."
    },

    "Node5": {
        "IP": "1.2.3.5",
        "port": 1234,
        "flags": ["Guard","Middle","Exit"],         
        "pubkey": "112233445566..."
    },

    "Node6": {
        "IP": "1.2.3.6",
        "port": 1234,
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


def TLS_with_guard(ip:str, port: int):
    try: 
        raw_guard_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl._create_unverified_context()
        ssl_guard_sock = context.wrap_socket(raw_guard_sock, server_hostname=ip)
        ssl_guard_sock.connect((ip, port))
        return ssl_guard_sock
    except Exception as e:
        print(f"Unable to establish TLS connection with {ip}:{port}: {e}")


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
        "listener_event": threading.Event()
    }
    
    return circID
    

def build_new_circuit(guard_sslsock : ssl.SSLSocket):

    circID = circuit_init()
    
    for i in range(3):
        if(not add_hop(circID, guard_sslsock)):
            print("add_hop failed. Exiting")
            return None
        
    
    circuits[circID]["status"] = "ACTIVE" 
    print(f"Circuit {circID} is active")      
    

def build_CREATE2_cell(circID: int, public_key : bytes) -> bytes:
    HTYPE = 2
    HLEN = len(public_key)
    create_payload = struct.pack(">HH32s", HTYPE,HLEN,public_key)
    create_cell = cell.pack_cell(circID,cell.CellCmd.CREATE,create_payload)
    return create_cell


def build_EXTEND_cell_payload(ip : str, port : int, public_key : bytes) -> bytes:
    dest_ip = socket.inet_aton(ip)
    relay_cell_payload = struct.pack(">4sH32s",dest_ip,port, public_key)
    return relay_cell_payload

def build_EXTEND_cell_for_Middle(circID: int, circuit_status :dict, public_key:bytes) -> bytes:
    middle_relay = selected_relays[1]
    middle_relay_ip, middle_relay_port = node_info(middle_relay)

    extend_relay_payload = build_EXTEND_cell_payload(middle_relay_ip,middle_relay_port,public_key)
    fwd_hash_machine = circuit_status["hops"][0]["fwd_digest"]
    raw_extend_relay_cell = cell.pack_relayCell_with_digest(relayCmds.EXTEND,0,extend_relay_payload,fwd_hash_machine)
    
    fwd_aes_machine = circuit_status["hops"][0]["fwd_cipher"]
    encrypted_extend_relay_cell = fwd_aes_machine.update(raw_extend_relay_cell)
    
    encrypted_extend_circuit_cell = cell.pack_cell(circID,cellCmds.RELAY,encrypted_extend_relay_cell)
    return encrypted_extend_circuit_cell
    
    
def build_EXTEND_cell_for_Exit(circID: int, circuit_status :dict, public_key:bytes) -> bytes:
    exit_relay = selected_relays[1]
    exit_relay_ip, exit_relay_port = node_info(exit_relay)

    extend_relay_payload = build_EXTEND_cell_payload(exit_relay_ip,exit_relay_port,public_key)
    fwd_hash_machine = circuit_status["hops"][1]["fwd_digest"]
    raw_extend_relay_cell = cell.pack_relayCell_with_digest(relayCmds.EXTEND,0,extend_relay_payload,fwd_hash_machine)
    
    middle_fwd_aes_machine = circuit_status["hops"][1]["fwd_cipher"]
    encrypted_extend_relay_cell = middle_fwd_aes_machine.update(raw_extend_relay_cell)
    
    guard_fwd_aes_machine = circuit_status["hops"][0]["fwd_cipher"]
    final_encrypted_extend_relay_cell = guard_fwd_aes_machine.update(encrypted_extend_relay_cell)
    encrypted_extend_circuit_cell = cell.pack_cell(circID,cellCmds.RELAY,final_encrypted_extend_relay_cell)
    return encrypted_extend_circuit_cell

def add_hop(circID: int, guard_sslsock : ssl.SSLSocket):

    circuit_status = circuits[circID]
    private_key, public_key = crypto.generate_ecdh_keypair()
    circuits[circID]["tmp_private_key"] = private_key
    circuit_status["listener_event"].clear()

    hops_len = len(circuit_status["hops"])

    if hops_len == 0:
        create_cell = build_CREATE2_cell(circID, public_key)
        guard_sslsock.sendall(create_cell)
    
    elif hops_len == 1:
        encrypted_extend_circuit_cell = build_EXTEND_cell_for_Middle(circID, circuit_status,public_key)
        guard_sslsock.sendall(encrypted_extend_circuit_cell)

    elif hops_len == 2:
        encrypted_extend_circuit_cell = build_EXTEND_cell_for_Exit(circID, circuit_status,public_key)
        guard_sslsock.sendall(encrypted_extend_circuit_cell)    

   
    success = circuit_status["hop_ready_event"].wait(timeout=5.0)
    if not success:
        print(f"Unable to build hop {hops_len + 1} for circuit")
        return False
        
    print(f"Hop {hops_len + 1} is created")
    return True
    
def decrypt_relay_cell(circ_data,relay_cell):
    constructed_hops = circ_data["hops"]
    constructed_hops_len = len(constructed_hops)
    digest_machine = constructed_hops[-1]["bwd_digest"]
    for i in range(constructed_hops_len):
        decryption_cipher = constructed_hops[i]["bwd_cipher"]
        decrypted_relay_cell = decryption_cipher.update(relay_cell)
    
    return decrypted_relay_cell,digest_machine

    
    
def handle_public_key(circ_data,relay_pub_key):
    try:
        shared_secret = crypto.compute_shared_secret(circ_data["tmp_private_key"], relay_pub_key)
        fwd_digest_key, bwd_digest_key, fwd_aes_key, bwd_aes_key = crypto.derive_tor_keys(circ_data, shared_secret)

        circ_data["tmp_private_key"] = None


        fwd_cipher, bwd_cipher = crypto.create_client_ciphers(fwd_aes_key, bwd_aes_key)
        fwd_digest, bwd_digest = crypto.create_running_digests()

        fwd_digest.update(fwd_digest_key)
        bwd_digest.update(bwd_digest_key)

        new_hop = {
            "fwd_cipher": fwd_cipher,
            "bwd_cipher": bwd_cipher,
            "fwd_digest": fwd_digest,
            "bwd_digest": bwd_digest
        }

        circ_data["hops"].append(new_hop)

        circ_data["hop_ready_event"].set()
    except Exception as e:
        print(f"Error when deriving relay public key : {e}")
    

     
def handle_RELAY(circ_data,recvd_relay_cell):
    decrypted_relay_cell,digest_machine = decrypt_relay_cell(circ_data,recvd_relay_cell)
    relayCmd, recognized, streamID,digest,length,data = cell.unpack_relay_cell(decrypted_relay_cell)
    
    if((not cell.verify_relay_cell(digest_machine,decrypted_relay_cell)) or recognized != 0):
        print("handle_RELAY(): Digest not matched")
        return None
    
    
    if(relayCmd == relayCmds.EXTENDED):
        relay_public_key = data[:32]
        handle_public_key(circ_data, relay_public_key)
        
        
    
def handle_CREATED(circ_data, payload):
    HTYPE,HLEN = struct.unpack(">HH",payload[:4])
    assert HTYPE == 2, "Invalid HTYPE"
    assert HLEN == 32, "Invalid Key Length"
    relay_pub_key = payload[4:4+HLEN]
    assert len(relay_pub_key) == 32, "Invalid Key Length"

    
    
    shared_secret = crypto.compute_shared_secret(circ_data["tmp_private_key"], relay_pub_key)
    fwd_digest_key, bwd_digest_key, fwd_aes_key, bwd_aes_key = crypto.derive_tor_keys(circ_data, shared_secret)

    circ_data["tmp_private_key"] = None

   
    fwd_cipher, bwd_cipher = crypto.create_client_ciphers(fwd_aes_key, bwd_aes_key)
    fwd_digest, bwd_digest = crypto.create_running_digests()

    fwd_digest.update(fwd_digest_key)
    bwd_digest.update(bwd_digest_key)

    new_hop = {
        "role" : "Guard",
        "ip" : selected_relays[0]["IP"],
        "port": selected_relays[0]["port"],
        "fwd_cipher": fwd_cipher,
        "bwd_cipher": bwd_cipher,
        "fwd_digest": fwd_digest,
        "bwd_digest": bwd_digest
    }

    circ_data["hops"].append(new_hop)
    
    circ_data["hop_ready_event"].set()

    print(f"Added new hop to circuit {circ_data}")






def listen_to_guard(guard_sslsock):
    while True:
        cell = guard_sslsock.recv(512)
        circID, cellCmd, payload = struct.unpack(">HB509s", cell)
        circ_data = selected_relays[circID]
        
        if cellCmd == cellCmds.CREATED:
            handle_CREATED(circ_data,payload)
            
        elif cellCmd == cellCmds.RELAY:
            handle_RELAY(circ_data,payload)
            
            

       
            


def init():
    #Node selection
    selected_relays = select_relays(MOCK_CONSENSUS)
    
    if(selected_relays == None):
        print("Program Ended : Not Enough available relays")
    
    #TLS with guard
    guard = selected_relays[0]
    guard_ip, guard_port = node_info(guard)
    guard_sslsock = TLS_with_guard(guard_ip, guard_port)

    new_circID = build_new_circuit(guard_sslsock)
    if(new_circID == None):
        print("Unable to create new circuit. Exiting")
        return 
    
    

    



if __name__ == "__main__":
    init()
   
    
    
            
    
        

        
        

        
        
        
        
    
    
    
    
    
    
