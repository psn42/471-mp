import socket
import ssl

def start_tls_server(host='localhost', port=8443, certfile='server.crt', keyfile='server.key'):
    # Create the SSL context for the server
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    # Set up the standard socket
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.bind((host, port))
    bindsocket.listen(5)
    print(f"Listening for TLS connections on {host}:{port}")

    while True:
        newsocket, fromaddr = bindsocket.accept()
        print(f"Accepted connection from {fromaddr}")
        
        # Wrap the accepted socket with the SSL context to establish TLS
        try:
            conn = context.wrap_socket(newsocket, server_side=True)
            print("TLS connection established.")
            
            # Read and automatically decrypt the payload
            data = conn.recv(1024)
            if data:
                print(f"Decrypted payload: {data}")
                
            # Optionally send a response
            # conn.sendall(b"Payload received over TLS")
        except ssl.SSLError as e:
            print(f"SSL error: {e}")
        finally:
            conn.close()

if __name__ == '__main__':
    # You will need a server.crt and server.key in the same directory.
    start_tls_server()
