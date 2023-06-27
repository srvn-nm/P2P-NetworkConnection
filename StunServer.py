import json
import socket
import threading
import redis
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# Check if data is string and send/receive it without Pillow library and via TCP connection
def is_string_data(data):
    return isinstance(data, str)

# Use Redis library for Redis Cluster operations

redis_client = redis.Redis(host='localhost', port=6379)

# Custom exception for Redis connection errors
class RedisConnectionError(Exception):
    pass

# Check if Redis connection is available
def check_redis_connection():
    try:
        redis_client.ping()
    except redis.exceptions.RedisClusterException:
        raise RedisConnectionError("Failed to connect to Redis Cluster")


# def process_non_string_message(message):
#     # Process non-string data (e.g., images) via UDP and Pillow library
#     # Implement your logic here
#     print("Processing non-string message:", message)
#
#
# def process_string_message(message):
#     # Process string data via TCP
#     # Implement your logic here
#     print("Processing string message:", message)
#     return {"status": "success"}  # Example response
#
#
# def process_message(message, conn):
#     # Check if the data is string and send/receive via TCP
#     if is_string_data(message):
#         response = process_string_message(message)
#         if response:
#             conn.sendall(json.dumps(response).encode())
#     else:
#         process_non_string_message(message)
#
#
# class P2PServer:
#     def __init__(self, ip_address, tcp_handshake_port):
#         self.ip_address = ip_address
#         self.tcp_handshake_port = tcp_handshake_port
#         self.tcp_sock = None
#         self.udp_sock = None
#         self.stop_event = threading.Event()
#
#     def start(self):
#         # Create TCP socket for handshake
#         self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#         self.tcp_sock.bind((self.ip_address, self.tcp_handshake_port))
#         self.tcp_sock.listen()
#
#         # Create UDP socket for data transfer
#         self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         self.udp_sock.bind((self.ip_address, 0))
#
#         # Start listening for incoming connections and data transfer requests
#         threading.Thread(target=self.accept_connections).start()
#
#     def stop(self):
#         # Close the TCP and UDP sockets
#         if self.tcp_sock:
#             self.tcp_sock.close()
#         if self.udp_sock:
#             self.udp_sock.close()
#
#         # Set the stop event to stop all threads
#         self.stop_event.set()
#
#     def accept_connections(self):
#         while not self.stop_event.is_set():
#             try:
#                 # Wait for a TCP connection
#                 conn, addr = self.tcp_sock.accept()
#                 print("Client connected:", addr[0], ":", addr[1])
#
#                 # Start a thread to handle the client connection
#                 threading.Thread(target=self.handle_connection, args=(conn,)).start()
#             except OSError:
#                 break
#
#     def handle_connection(self, conn):
#         while not self.stop_event.is_set():
#             try:
#                 # Receive data from the client
#                 data = conn.recv(1024)
#                 if not data:
#                     break
#
#                 # Process the received data
#                 message = json.loads(data.decode())
#                 process_message(message, conn)
#             except ConnectionError:
#                 break
#             except json.JSONDecodeError:
#                 print("Invalid JSON data received")
#
#         # Close the connection
#         conn.close()
#
#     def send_message(self, message, dest_ip, dest_port):
#         # Send a message to the destination IP and port via UDP
#         if self.stop_event.is_set():
#             return
#
#         message_data = {"message": message}
#         message_bytes = json.dumps(message_data).encode()
#         self.udp_sock.sendto(message_bytes, (dest_ip, dest_port))


# Define the handler for incoming HTTP requests
class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global CODE
        msg = {}
        # print('do_GET')
        query_components = parse_qs(urlparse(self.path).query)
        # print(query_components)

        if '/getAll' in self.path:
            # print('getAll')
            try:
                usernames = str(redis_client.keys('*'))
                # print(usernames)
                if len(usernames) > 0:
                    CODE = 200
                    msg = {'peers' : usernames}
                else:
                    CODE = 404
                    msg = {'error' : 'no peers around >-<'}

            except:
                CODE = 500
                msg ={'error' : 'Server is not working!'}

            self.send_response(CODE)
            self.send_header('Content-type', 'application/json')  # Change content-type to 'application/json'
            self.end_headers()
            self.wfile.write(json.dumps(msg).encode('utf-8')) # Serialize usernames_list to JSON

        elif '/getIp' in self.path:
            # print('getIp')
            try:
                username = query_components.get('username', [''])[0]
                # print(username)
                ip_address = redis_client.get(username)
                # print(str(ip_address)+'meow')
                # print(query_components.get('address', [''])[0])
                # print(ip_address.decode('utf-8'))
                if not ip_address.decode('utf-8'):
                    CODE = 404
                    msg = {'error' : 'not found'}
                elif not username or not query_components.get('address', ['']):
                    CODE = 400
                    msg = {'error' : 'incorrect username or address'}
                elif ip_address.decode('utf-8'):
                    CODE = 200
                    msg = {"ip" : ip_address.decode('utf-8')}

            except:
                CODE = 500
                msg = {'error' : 'Server is not working!'}

            self.send_response(CODE)
            self.send_header('Content-type', 'application/json')  # Change content-type to 'application/json'
            self.end_headers()
            self.wfile.write(json.dumps(msg).encode('utf-8')) # Serialize ip_address to JSON
            # print(msg)
        else:
            # Send a 404 Not Found response
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'404 Not Found')

    def do_POST(self):
        # print('do_POST')
        global CODE
        msg = {}
        content_length = int(self.headers['Content-Length'])
        # print(content_length)
        body = self.rfile.read(content_length)
        # print(body)

        form_data = json.loads(body.decode())
        # print(form_data)
        # print(redis_client.get(form_data['username']))
        if '/init' in self.path:
            # print('init')
            try:
                if not form_data['username'] or not form_data['ip'] or redis_client.get(form_data['username']) == form_data['ip']:
                    CODE = 400
                    msg = {'error' : 'incorrect username or ip!'}
                elif redis_client.get(form_data['username']) == form_data['ip']:
                    msg = {'error' : 'already registered!'}
                else:
                    username = form_data.get('username', [''])
                    ip = form_data.get('ip', [''])
                    redis_client.set(username, ip)
                    CODE = 200
                    msg = {"username": username, "ip": ip}

            except:
                CODE = 500
                msg = {'error' : 'Server is not working!'}

            self.send_response(CODE)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            self.wfile.write(json.dumps(msg).encode('utf-8'))
        else:
            # Send a 404 Not Found response
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'404 Not Found')


# Start the HTTP server
if __name__ == '__main__':
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f'Starting server on https://{server_address[0]}:{server_address[1]}')
    threading.Thread(target=check_redis_connection).start()

    # p2p_server = P2PServer(socket.gethostbyname(socket.gethostname()), 10000)
    # p2p_server.start()

    httpd.serve_forever()
