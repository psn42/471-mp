import SimpleTor_cell


import socket
import ssl
import secrets

import time


RELAY_SEARCH_TIMEOUT = 1

MOCK_CONSENSUS = {
    "Node1": {
        "ip": "10.0.0.1",         
        "port": 9001,              
        "flags": ["Guard", "Middle"], 
        "onion_pubkey_hex": "a1b2c3d4e5f6..." 
    },

    "Node2": {
        "ip": "10.0.0.2",
        "port": 9001,
        "flags": ["Middle","Exit"],
        "onion_pubkey_hex": "f6e5d4c3b2a1..."
    },

    "Node3": {
        "ip": "10.0.0.3",
        "port": 9001,
        "flags": ["Guard","Exit"],         
        "onion_pubkey_hex": "112233445566..."
    },

      "Node4": {
        "ip": "10.0.0.4",
        "port": 9001,
        "flags": ["Middle","Guard"],         
        "onion_pubkey_hex": "1241245512555..."
    },

    "Node5": {
        "ip": "10.0.0.5",
        "port": 9001,
        "flags": ["Guard","Middle","Exit"],         
        "onion_pubkey_hex": "112233445566..."
    },

    "Node6": {
        "ip": "10.0.0.6",
        "port": 9001,
        "flags": ["Guard","Middle","Exit"],         
        "onion_pubkey_hex": "112233445566..."
    }    
    
}

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


def TLS_with_guard(ip:str, port: int):
    raw_guard_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl._create_unverified_context()
    ssl_guard_sock = context.wrap_socket(raw_guard_sock, server_hostname=ip)
    ssl_guard_sock.connect((ip, port))
    return ssl_guard_sock

def build_circuit_with_guard(guard_sslsock : ssl.SSLSocket):
    circID = secrets.randbelow(65535) + 1




if __name__ == "__main__":
    selected = select_relays(MOCK_CONSENSUS)
    if(selected == None):
        print("Program Ended : Not Enough available relays")
    print(selected)
   
    
    
            
    
        

        
        

        
        
        
        
    
    
    
    
    
    
