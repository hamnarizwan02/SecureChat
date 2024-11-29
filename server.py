import socket
import threading
import json
import hashlib
import os
import base64
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

class ChatServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen()
        self.clients = {}
        self.credentials_file = "creds.txt"
        
    def start(self):
        print("Server is running... :)")
        while True:
            client_socket, address = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            thread.start()
            
    def handle_client(self, client_socket):
        try:
            while True:  #same client until they choose to exit
                #initial Diffie-Hellman key exchange
                dh = DiffieHellman()
                public_key = dh.generate_public_key()
                client_socket.send(str(public_key).encode())
                client_public_key = int(client_socket.recv(1024).decode())
                shared_key = str(dh.generate_shared_secret(client_public_key))
                
                #registration/login 
                while True:
                    try:
                        encrypted_choice = client_socket.recv(1024)
                        if not encrypted_choice:  #client disconnected?
                            return
                            
                        choice = self.decrypt_message(encrypted_choice, shared_key)
                        
                        if choice == "register":
                            self.handle_registration(client_socket, shared_key)
                            break
                        elif choice == "login":
                            if self.handle_login(client_socket, shared_key):
                                return  #exit after successful chat session
                            break
                        elif choice == "exit":
                            return
                    except Exception as e:
                        print(f"Error in client loop: {e}")
                        break
                        
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            print("Client disconnected")
            client_socket.close()
            
    def handle_registration(self, client_socket, shared_key):
        try:
            #receive encrypted registration data from client
            encrypted_data = client_socket.recv(1024)
            data = json.loads(self.decrypt_message(encrypted_data, shared_key))
            
            email = data['email']
            username = data['username']
            password = data['password']
            
            #does username already exist?
            if self.username_exists(username):
                response = self.encrypt_message("Username already exists", shared_key)
                client_socket.send(response)
                return False
                
            #generate salt and hash password
            salt = os.urandom(32)
            hashed_password = self.hash_password(password, salt)
            
            #store credentials in creds.txt
            with open(self.credentials_file, "a") as f:
                f.write(f"{email},{username},{base64.b64encode(hashed_password).decode()},{base64.b64encode(salt).decode()}\n")
                
            response = self.encrypt_message("Registration successful", shared_key)
            client_socket.send(response)
            return True
            
        except Exception as e:
            print(f"Registration error: {e}")
            return False
            
    def handle_login(self, client_socket, shared_key):
        try:
            #receive encrypted login data from client
            encrypted_data = client_socket.recv(1024)
            data = json.loads(self.decrypt_message(encrypted_data, shared_key))
            
            username = data['username']
            password = data['password']
            
            #verify credentials of user 
            if self.verify_credentials(username, password):
                response = self.encrypt_message("Login successful", shared_key)
                client_socket.send(response)
                
                #new key exchange for chat
                new_dh = DiffieHellman()
                new_public_key = new_dh.generate_public_key()
                client_socket.send(str(new_public_key).encode())
                new_client_public_key = int(client_socket.recv(1024).decode())
                chat_shared_key = str(new_dh.generate_shared_secret(new_client_public_key)) + username
                
                self.handle_chat(client_socket, chat_shared_key)
                return True
            else:
                response = self.encrypt_message("Invalid credentials", shared_key)
                client_socket.send(response)
                return False
                
        except Exception as e:
            print(f"Login error: {e}")
            return False

    def handle_chat(self, client_socket, shared_key):
        while True:
            try:
                #receive and decrypt message from client
                encrypted_message = client_socket.recv(1024)
                if not encrypted_message:
                    break
                    
                #decrypt the client message
                client_message = self.decrypt_message(encrypted_message, shared_key)
                print(f"Client: {client_message}")
                
                if client_message.lower() == 'bye':
                    break

                #print receive msg ack
                response_ack = f"Server received: {client_message}"
                encrypted_ack = self.encrypt_message(response_ack, shared_key)
                client_socket.sendall(encrypted_ack)

                #server's turn to send a msg imme
                server_message = input("Server: ")
                encrypted_server_message = self.encrypt_message(server_message, shared_key)
                client_socket.sendall(encrypted_server_message)
                
                if server_message.lower() == 'bye':
                    break

            except Exception as e:
                print(f"Chat error: {e}")
                break
                
    def username_exists(self, username):
        if not os.path.exists(self.credentials_file):
            return False
            
        with open(self.credentials_file, "r") as f:
            for line in f:
                if username in line:
                    return True
        return False
        
    def hash_password(self, password, salt):
        return hashlib.sha256(password.encode() + salt).digest()
        
    def verify_credentials(self, username, password):
        if not os.path.exists(self.credentials_file):
            return False
            
        with open(self.credentials_file, "r") as f:
            for line in f:
                email, stored_username, stored_hash, stored_salt = line.strip().split(',')
                if username == stored_username:
                    salt = base64.b64decode(stored_salt)
                    hashed_password = self.hash_password(password, salt)
                    return base64.b64encode(hashed_password).decode() == stored_hash
        return False
        
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
    server = ChatServer()
    server.start()