import SimpleTor_cell as cell
import SimpleTor_crypto_utils as crpyto

import socket
import ssl
import secrets
import time
import struct
import threading

RELAY_SEARCH_TIMEOUT = 1

MOCK_CONSENSUS = {
    "Node1": {
        "IP": "10.0.0.1",         
        "port": 9001,              
        "flags": ["Guard", "Middle"], 
        "pubkey": "a1b2c3d4e5f6..." 
    },

    "Node2": {
        "IP": "10.0.0.2",
        "port": 9001,
        "flags": ["Middle","Exit"],
        "pubkey": "f6e5d4c3b2a1..."
    },

    "Node3": {
        "IP": "10.0.0.3",
        "port": 9001,
        "flags": ["Guard","Exit"],         
        "pubkey": "112233445566..."
    },

      "Node4": {
        "IP": "10.0.0.4",
        "port": 9001,
        "flags": ["Middle","Guard"],         
        "pubkey": "1241245512555..."
    },

    "Node5": {
        "IP": "10.0.0.5",
        "port": 9001,
        "flags": ["Guard","Middle","Exit"],         
        "pubkey": "112233445566..."
    },

    "Node6": {
        "IP": "10.0.0.6",
        "port": 9001,
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
    node_ip = node["ip"]
    node_port = node["port"]
    node_ppubkey = node["pubkey"]
    return node_ip, node_port, node_ppubkey


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
    private_key, public_key = crpyto.generate_ecdh_keypair()
    circuits[circID]["tmp_private_key"] = private_key
    circuit_status["listener_event"].clear()

    hops_len = len(circuit_status["hops"])

    if hops_len == 0:
        create_cell_payload = build_CREATE2_cell(public_key)
        create_cell = cell.pack_cell(circID,cell.CellCmd.CREATE,create_cell_payload)
        guard_sslsock.sendall(create_cell)



    elif hops_len == 1  :
        middle_ip, middle_port = node_info(selected_relays[1])
        extend_cell_payload = build_EXTEND_cell_payload(middle_ip,middle_port, public_key)
        extend_cell = cell.pack_relayCell(cell.RelayCmd.EXTEND,0,extend_cell_payload)

    
        


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
   
    
    
            
    
        

        
        

        
        
        
        
    
    
    
    
    
    
