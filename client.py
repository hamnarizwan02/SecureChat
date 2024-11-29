import socket
import json
import base64
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class DiffieHellman:
    def __init__(self, p=23, g=5):
        self.p = p
        self.g = g
        self.private_key = int.from_bytes(os.urandom(4), 'big') % self.p
        
    def generate_public_key(self):
        return pow(self.g, self.private_key, self.p)
    
    def generate_shared_secret(self, other_public_key):
        return pow(other_public_key, self.private_key, self.p)

class ChatClient:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        
    def connect(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))
        
    def start(self):
        try:
            self.connect()
            while True:
                #initial Diffie-Hellman key exchange
                dh = DiffieHellman()
                server_public_key = int(self.client.recv(1024).decode())
                self.client.send(str(dh.generate_public_key()).encode())
                self.shared_key = str(dh.generate_shared_secret(server_public_key))
                
                print("\n1. Register")
                print("2. Login")
                print("3. Exit")
                choice = input("Enter your choice: ")
                
                if choice == "1":
                    self.register()
                elif choice == "2":
                    if self.login():
                        self.chat()
                        self.connect() 
                elif choice == "3":
                    encrypted_choice = self.encrypt_message("exit", self.shared_key)
                    self.client.send(encrypted_choice)
                    break
                    
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            self.client.close()
            
    def register(self):
        try:
            #send server -> registration choice
            choice = self.encrypt_message("register", self.shared_key)
            self.client.send(choice)
            
            #get user details
            email = input("Enter email: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            
            #sending encrypted registration data to server
            data = {
                "email": email,
                "username": username,
                "password": password
            }
            encrypted_data = self.encrypt_message(json.dumps(data), self.shared_key)
            self.client.send(encrypted_data)
            
            #getting response
            response = self.decrypt_message(self.client.recv(1024), self.shared_key)
            print(response)
            
        except Exception as e:
            print(f"Registration error: {e}")
            self.connect()  #reconnect on error
            
    def login(self):
        try:
            #send server -> login choice
            choice = self.encrypt_message("login", self.shared_key)
            self.client.send(choice)
            
            #get user details
            username = input("Enter username: ")
            password = input("Enter password: ")
            
            #send encrypted login data
            data = {
                "username": username,
                "password": password
            }
            encrypted_data = self.encrypt_message(json.dumps(data), self.shared_key)
            self.client.send(encrypted_data)
            
            #getting response
            response = self.decrypt_message(self.client.recv(1024), self.shared_key)
            print(response)
            
            if response == "Login successful":
                #new key exchange for chat
                dh = DiffieHellman()
                server_public_key = int(self.client.recv(1024).decode())
                self.client.send(str(dh.generate_public_key()).encode())
                self.shared_key = str(dh.generate_shared_secret(server_public_key)) + username
                return True
            return False
            
        except Exception as e:
            print(f"Login error: {e}")
            self.connect()  #reconnect on error
            return False

    def chat(self):
        print("\nChat started (type 'bye' to exit)")
        while True:
            try:
                #client's turn to send a message
                message = input("You: ")
                encrypted_message = self.encrypt_message(message, self.shared_key)
                self.client.sendall(encrypted_message)
                
                if message.lower() == 'bye':
                    break

                #immediately receive server's ack n response
                encrypted_response = self.client.recv(1024)
                response = self.decrypt_message(encrypted_response, self.shared_key)
                print(f"Server: {response}")

                #check for another server response -> if server sends multiple msg
                encrypted_response = self.client.recv(1024)
                if encrypted_response:
                    response = self.decrypt_message(encrypted_response, self.shared_key)
                    print(f"Server: {response}")

            except Exception as e:
                print(f"Chat error: {e}")
                break
                
    def encrypt_message(self, message, key):
        key = hashlib.sha256(key.encode()).digest()[:16]
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
        return base64.b64encode(iv + encrypted)
        
    def decrypt_message(self, encrypted_message, key):
        key = hashlib.sha256(key.encode()).digest()[:16]
        encrypted = base64.b64decode(encrypted_message)
        iv = encrypted[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted[16:]), AES.block_size)
        return decrypted.decode()

if __name__ == "__main__":
    client = ChatClient()
    client.start()