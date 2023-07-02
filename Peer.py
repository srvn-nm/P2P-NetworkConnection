import json
import socket
import threading

import PIL
from PIL import *
import requests
import io

from PIL import Image


def is_port_busy(port):
    try:
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.settimeout(1)
        tcp_socket.bind(("localhost", port))
        tcp_socket.close()
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.settimeout(1)
        udp_socket.bind(("localhost", port))
        udp_socket.close()
        return False
    except socket.error:
        return True


class Peer:
    def __init__(self):
        self.terminateFlag = True
        self.tcp_handshake_port = 10000
        self.hostname = socket.gethostname()
        self.ip_address = socket.gethostbyname(self.hostname)
        self.init_url = 'http://127.0.0.1:8080/init'
        self.get_usernames = 'http://127.0.0.1:8080/getAll'
        self.get_ip = 'http://127.0.0.1:8080/getIp?username='
        t1 = threading.Thread(target=self.listener, args=(self.ip_address,))
        t1.start()

    def listener(self, k):

        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_address = (self.ip_address, self.tcp_handshake_port)
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind(local_address)
        # print('local address: '+str(local_address))
        while True:
            tcp_socket.listen(2)
            client_sock, client_address = tcp_socket.accept()
            data = client_sock.recv(1024).decode('utf-8')
            data = data.split(':')
            # print("data in listener: " + str(data))
            dest_ip = data[0]
            dest_port = data[1]
            dest_filename = data[2]
            # inp = input(f"A system with IP {client_address} wants to connect you and receive '{dest_filename}', do you want to accept?\n1. Yes\n2. No\nInput: ")
            print(f"A system with IP {client_address} wants to connect you and receive '{dest_filename}'")
            self.terminateFlag = False
            while True:
                # print(f"{inp} is input in listener!")
                # if inp == '1':
                try:
                    # print(100)
                    # client_sock.bind((self.ip_address, int(dest_port)))
                    client_sock.sendall(b"Done")
                    # print(101)
                    threading.Thread(target=self.file_sender, args=(dest_ip, dest_port, dest_filename, client_sock)).start()
                    # print('option 1 in listener')
                    break
                # elif inp == '2':
                except Exception as e:
                    # print(102)
                    print(e)
                    # client_sock.bind((self.ip_address, int(dest_port)))
                    client_sock.sendall(b"None")
                    # print('option 2 in listener')
                    break
                else:
                    print('Invalid input!')
                # inp = input(f"A system with IP {client_address} wants to connect you and receive '{dest_filename}', do you want to accept?\n1. Yes\n2. No\nInput: ")
            tcp_socket.close()
            self.terminateFlag = True
            self.run()

    def file_sender(self, dest_ip, dest_port, dest_filename, udp_socket):
        HOST = dest_ip
        # print(f'this is host in file sender {HOST}')
        PORT = int(dest_port)
        # print(f'this is port in file sender {PORT}')
        BUFFER_SIZE = 1024

        is_string = True

        try:
            # print(403)
            image = Image.open('./files/' + dest_filename)
            # print(404)
            data = image.tobytes()
            # print(405)
            if '.jpg' in dest_filename or '.jpeg' in dest_filename or '.png' in dest_filename or '.gif' in dest_filename:
                is_string = False
        except PIL.UnidentifiedImageError:
            try:
                # print(400)
                with open('./files/' + dest_filename, 'rb') as f:
                    # print(401)
                    data = f.read()
                    # print(data.decode())
                    # print(402)
                    is_string = True

            except FileNotFoundError:
                print("File couldn't be found! >-<")
                return


        #
        # print(f'encoded message is: {encoded_message}')
        if not is_string:
            # Send image data over UDP connection
            # udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # print(406)
            for i in range(0, len(data), BUFFER_SIZE):
                # print(407)
                chunk = data[i:i + BUFFER_SIZE]
                # print(PORT)
                try:
                    udp_socket.sendto(chunk, (HOST, PORT))
                except Exception as e:
                    print(e)
                    print('error in sending chunks!')
                # print(408)

            # print(409)
            udp_socket.sendto(b'', (HOST, PORT))
            # print(410)
            udp_socket.close()
        else:
            # tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # udp_socket.connect((socket.gethostbyname(socket.gethostname()), PORT))
            # Send the message over TCP connection
            encoded_message = json.dumps(data.decode()).encode()
            udp_socket.sendall(encoded_message)
            udp_socket.close()

        print('Everything transferred successfully ^-^')
        self.run()

    def file_receiver(self, my_ip, target_ip, filename):
        self.terminateFlag = False
        empty_port = 1
        for ip in range(10001, 10012):
            if not is_port_busy(ip):
                empty_port = ip
        if empty_port == 1:
            print("You can't connect to ports right now! >-<")
            return
        # print(f'{empty_port} is the empty port in file receiver')
        try:
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # print(1)
            port_and_ip = (my_ip, 10000)
            # print(2)
            tcp_socket.connect(port_and_ip)
            # print(3)
            message = f"{my_ip}:{empty_port}:{filename}"
            # print(4)
            tcp_socket.sendall(message.encode())
            # print(5)
            data = tcp_socket.recv(1024)
            # print(6)
            # print(data.decode())
            # print(7)
            try:
                tcp_socket.close()
                if data.decode() != 'Done':
                    response = json.loads(data.decode())
                    print('Response: \n' + response)
            except json.JSONDecodeError:
                # print(8)
                tcp_socket.close()
                # print(9)
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # print(10)
                udp_socket.bind((my_ip, empty_port))
                # print(11)
                # Process received image/video data over UDP connection
                chunks = []
                while True:
                    # print(empty_port)
                    chunk, addr = udp_socket.recvfrom(1024)
                    if not chunk:
                        break
                    # print(13)
                    chunks.append(chunk)

                # Combine the received chunks into a single byte string
                # print(14)
                data = b''.join(chunks)
                try:
                    # print(15)
                    received_image = Image.open(io.BytesIO(data))
                    # print(16)
                    received_image.show()
                    # print(17)
                    file = open(f'./file/{filename}', "wb")
                    # print(18)
                    file.write(data)
                    # print(19)
                except Exception as e:
                    print(e)
                    print("Error appeared while using the file!")

                udp_socket.close()
        except Exception as e:
            print(e)
            print('Error connecting to peers >-<')
        self.terminateFlag = True
        self.run()

    def init_action(self):
        # print('init_action')
        username = input("Enter a username:")
        data = {
            "username": username,
            "ip": self.ip_address
        }
        try:
            response = requests.post(self.init_url, json=data).text
        except:
            response = "error"
        print('HTTP Server Response:', response)

    def get_usernames_action(self):
        # print('get_usernames_action')
        try:
            response = requests.get(url=self.get_usernames).text
        except:
            response = "Error"
        print('HTTP Server Response:', response)

    def get_specific_ip_action(self):
        # print("get_specific_ip_action")
        target_username = input("Enter Target username:")
        try:
            response = requests.get(url=self.get_ip + target_username).text
        except:
            response = "Error"
        print('HTTP Server Response:', response)

    def request_for_connection_action(self):
        # print('request_for_connection_action')
        target_ip = input('Enter your target username: ')
        filename = input('Enter file route: ')
        threading.Thread(target=self.file_receiver, args=(self.ip_address, target_ip, filename)).start()

    def run(self):
        print(
            "Hello ^-^\nYou can connect others in here for transferring data!\nWhenever you want to exit press enter!")
        choice = input(
            'Choose one option below:\n1. Initialization\n2. Get near usernames\n3. Get specific IP\n4. Request for connection\nInput: ')
        while choice and self.terminateFlag:
            if choice == '1' and self.terminateFlag:
                self.init_action()
            elif choice == '2' and self.terminateFlag:
                self.get_usernames_action()
            elif choice == '3' and self.terminateFlag:
                self.get_specific_ip_action()
            elif choice == '4' and self.terminateFlag:
                self.request_for_connection_action()
                break
            else:
                print("Wrong choice! Please try again.")
            if self.terminateFlag:
                choice = input(
                    'Choose one option below:\n1. Initialization\n2. Get near usernames\n3. Get specific IP\n4. Request for connection\nInput: ')
            else:
                break


if __name__ == "__main__":
    peer = Peer()
    peer.run()
