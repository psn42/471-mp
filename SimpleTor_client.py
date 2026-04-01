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
    add_hop(circID, guard_sslsock) 
    

    


def build_CREATE2_cell(public_key : bytes) -> bytes:
    HTYPE = 2
    HLEN = len(public_key)
    create_payload = struct.pack(">HH32s", HTYPE,HLEN,public_key)
    return create_payload


def build_EXTEND_cell_payload(ip : str, port : int, public_key : bytes) -> bytes:
    dest_ip = socket.inet_aton(ip)
    relay_cell_payload = struct.pack(">4sH32s",dest_ip,port, public_key)
    return relay_cell_payload
    
    
    

def add_hop(circID: int, guard_sslsock : ssl.SSLSocket):

    circuit_status = circuits[circID]
    private_key, public_key = crypto.generate_ecdh_keypair()
    circuits[circID]["tmp_private_key"] = private_key
    circuit_status["listener_event"].clear()

    hops_len = len(circuit_status["hops"])

    if hops_len == 0:
        create_cell_payload = build_CREATE2_cell(public_key)
        create_cell = cell.pack_cell(circID,cell.CellCmd.CREATE,create_cell_payload)
        guard_sslsock.sendall(create_cell)

   
    success = circuit_status["hop_ready_event"].wait(timeout=5.0)
    if not success:
        print("[-] Error: Hop building timed out!")
        return False
        
    print("[+] Hop successfully built! Moving on.")
    return True
    

def handle_CREATED(circ_data, payload):
    HTYPE,HLEN = struct.unpack(">HH",payload[:4])
    assert HTYPE == 2, "Invalid HTYPE"
    assert HLEN == 32, "Invalid Key Length"
    relay_pub_key = payload[4:4+HLEN]
    assert len(relay_pub_key) == 32, "Invalid Key Length"

    
    # 2. Do the ECDH Math & derive AES keys
    shared_secret = crypto.compute_shared_secret(circ_data["tmp_private_key"], relay_pub_key)
    fwd_digest_key, bwd_digest_key, fwd_aes_key, bwd_aes_key = crypto.derive_tor_keys(circ_data, shared_secret)

    circ_data["tmp_private_key"] = None

    # 3. Clean up the private key
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
    # 4. WAKE UP THE MAIN THREAD!
    circ_data["hop_ready_event"].set()

    print(f"Added new hop to circuit {circ_data}")




def listen_to_guard(guard_sslsock):
    while True:
        cell = guard_sslsock.recv(512)
        circID, cellCmd, payload = struct.unpack(">HB509s", cell)
        circ_data = selected_relays[circID]
        
        
        if cellCmd == cellCmds.CREATED:
            handle_CREATED(circ_data,payload)

        
            


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

    



if __name__ == "__main__":
    init()
   
    
    
            
    
        

        
        

        
        
        
        
    
    
    
    
    
    
