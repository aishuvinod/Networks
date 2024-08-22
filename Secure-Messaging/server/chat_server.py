#!/usr/bin/env python3
import socket, argparse, json, getpass, random, base64, os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import sys
# setting path
sys.path.append('../')
# importing
from utils import *
import sys
import time
import threading
lockout_duration = 300  # Lockout duration in seconds

# Dictionary to store user information
users = {}
failed_attempts = {}

timeout_message = {"type": "error", 
                   "message": "User temporarily locked out. Try again later.", 
                   "login": "no"}

# Generate a random private key 'b'
def generate_private_key():
    return random.randint(1, 99999999)

# Generate a random nonce 'c1' 
def generate_nonce():
    return random.randint(1, 99999999)

# Generate a 32-bit number 'u'
def generate_u():
    return random.randint(0, (1 << 32) - 1)

# Function to compute g^b and g^W mod p to send back to client
#returns gb_mod_p + gW_mod_p and b 
def compute_server_response(g, p, verifier):
    b = generate_private_key()  # Random b
    gb_mod_p = pow(g, b, p)  # Compute g^b mod p
    gW_mod_p = verifier  # This is g^W mod p, already computed as the verifier
    return (gb_mod_p + gW_mod_p) % p, b

# Function to compute shared key where K = g^{b(a+uW}mod p 
def compute_shared_key(gamodp, b, u, verifier, p):
    # Compute the shared key K
    K_server = pow(gamodp * pow(verifier, u, p), b, p)
    return K_server

# Define a function to send check-in messages to clients
def send_checkin_messages(server_socket):
    while True:
        # Iterate over connected clients and send check-in message
        for addr in users.keys():
            checkin_message = {"type": "CHECK-IN"}
            server_socket.sendto(json.dumps(checkin_message).encode(), addr)
        # Wait for 10 seconds before sending the next check-in message
        time.sleep(5)


# handles all server operations
def server_program(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # get instance
    server_socket.bind(('127.0.0.1', port))
    print("Server Initialized...")

    # Start a thread to send check-in messages
    checkin_thread = threading.Thread(target=send_checkin_messages, args=(server_socket,))
    checkin_thread.daemon = True  
    checkin_thread.start()

    try:
        while True:
            conn, address = server_socket.recvfrom(65535)  # accept new connection
            data = json.loads(conn.decode())            
            print("from connected user: " + str(data) + "from " + str(address))
            message_type = data['type']

            # branches based on what type of packet we received
            if message_type == 'SIGN-IN':
                store_user(data, address, server_socket)
            if message_type == 'AUTH_MESSAGE':
                handle_auth_message(data, address, server_socket)
            elif message_type == 'list':
                list_users(server_socket, address)
            elif message_type == 'SEND':
                print(f"Received SEND from {address}, message: {data}")
                if address not in users:
                    print(f"Address {address} not found in users dict.")
                else:
                     handle_send_message(data, address, server_socket)
            elif message_type == 'exit':
                user_to_remove = None
                for addr, info in users.items():
                    if info["username"] == data['USERNAME']:
                        user_to_remove = addr
                        break
                if user_to_remove:
                    users.pop(user_to_remove)
    except KeyboardInterrupt:
        # Send goodbye message to all connected clients
        goodbye_message = {"type": "GOODBYE", "message": "Server is shutting down. Goodbye!"}
        for addr in users.keys():
            server_socket.sendto(json.dumps(goodbye_message).encode(), addr)
        print("\nServer shutting down...")
        server_socket.close()  # Close the server socket
        sys.exit(0)  # Exit the program
                       


# after a user logs in save their data to places it can be accessed later
def store_user(data, address, conn):
    username = data['username']
    gamodp = data['g^amodp']

    if (is_locked_out(username)):
        conn.sendto(json.dumps(timeout_message).encode(), address)
        
    # Load server configuration and user database to get the p,g, and verifier of the user
    with open('users.json', 'r') as f:
        user_db = json.load(f)
    
    p = int(user_db['p'])
    g = int(user_db['g'])
    try:
        verifier = int(user_db['users'][username]['verifier'])  # This is g^W mod p
    except KeyError:
        message = {"type": "error", "message": "User not found", "login": "yes"}         
        conn.sendto(json.dumps(message).encode(), address)
        return

    # Compute server response values
    gb_plus_gW_mod_p, b = compute_server_response(g, p, verifier)
    u = generate_u()
    c_1 = generate_nonce()

    # Send server response to client
    response = {
        "type": "SRP_RESPONSE",
        "g^b+g^W_mod_p": gb_plus_gW_mod_p,
        "u": u,
        "c_1": c_1
    }
    conn.sendto(json.dumps(response).encode(), address)

    #Shared key
    # Compute shared key using gamodp from client, b and u from server, and verifier gWmodp from user's stored data
    K_server = compute_shared_key(gamodp, b, u, verifier, p)
    
    online = fetch_usernames()
    if username in  online:
        message = {"type": "error", "message": "User already logged in", "login": "yes"}   
        conn.sendto(json.dumps(message).encode(), address)
    else:
        users[address] = {
            "username": username,
            "K_server": K_server,
            "c1": c_1
            }
        
    
# Updates running count if password is incorrect
# starts 5 minute lockout 
def check_fails(user):
    if user in failed_attempts.keys():
        failed_attempts[user] += 1
        if failed_attempts[user] >= 3:
            # Set lockout timestamp
            failed_attempts[user] = time.time()
    else:
        failed_attempts[user] = 1


# determines if a user is currently locked out
def is_locked_out(user):
    if user in failed_attempts.keys():
        if failed_attempts[user] >= 3:
            # Check if lockout duration has passed
            if time.time() - failed_attempts[user] < lockout_duration:
                return True
            else:
                # Reset failed attempts after lockout duration
                del failed_attempts[user]
    return False

# handling for AUTH_MESSAGE type where the server received the cnrypted c_1 and c_2 from the client.
# The server needs to make sure the c_1 is correct and then send back the encrypted c_2
def handle_auth_message(data, address, server_socket):
    if address in users:
        K_server = users[address]["K_server"]
        c_1 = users[address]["c1"]
        # Derive AES key from K_server
        K = derive_key(K_server)

        try:
            # Decrypt encrypted_c1
            encrypted_c1 = base64.b64decode(data['encrypted_c1'])
            decrypted_c1 = decrypt_with_key(K, encrypted_c1, False)
            # Convert decrypted_c1 from bytes to an integer
            decrypted_c1_int = int.from_bytes(decrypted_c1, byteorder='big')
            # Verify c_1 or perform necessary checks
            if c_1 != decrypted_c1_int:
                if is_locked_out(users[address]['username']):
                    server_socket.sendto(json.dumps(timeout_message).encode(), address)
                else:
                    failed_auth(address, server_socket)
            else:
                if is_locked_out(users[address]['username']):
                    server_socket.sendto(json.dumps(timeout_message).encode(), address)
                else:
                    # reset failed attemps upon succesful login
                    failed_attempts[users[address]['username']] = 0
                    # Encrypt c_2 received from the client to send back
                    c_2 = data['c_2']
                    # convert
                    c_2_bytes = c_2.to_bytes((c_2.bit_length() + 7) // 8, 'big')
                    # Encrypt c_1 with the derived symmetric key
                    encrypted_c2 = encrypt_with_key(K, c_2_bytes)
                    response = {
                        "type": "AUTH_RESPONSE",
                        "encrypted_c2": base64.b64encode(encrypted_c2).decode(),
                    }
                    server_socket.sendto(json.dumps(response).encode(), address)
        except InvalidTag:
            if is_locked_out(users[address]['username']):
                    server_socket.sendto(json.dumps(timeout_message).encode(), address)
            else:
                failed_auth(address, server_socket)
        
# returns all currently logged in users
def fetch_usernames():
    online = []
    for key in users:
        online.append(users[key]['username'])
    return online

# path if user validation fails
def failed_auth(address, server_socket):
    if address in users:
        username = users[address]['username']
        message = {"type": "error", "message": "User verification failed", "login": "yes"}
        check_fails(username)
        del users[address]
        server_socket.sendto(json.dumps(message).encode(), address)
    else:
        print(f"No user found at address {address}")



# lists all users currently online
def list_users(conn, address):
    user_list = ", ".join(user_info["username"] for user_info in users.values())
    data = f"<- Signed In Users: {user_list}"
    conn.sendto(data.encode(), address)

def get_addr(username):
    for key in users:
        if users[key]['username'] == username:
            return key


# Function to handle sending messages between clientsif message['type'] == 'SEND':
def handle_send_message(data, address, server_socket):
            # Check if address is in users
            if address in users:
                # Retrieve the shared key
                K_server = users[address]['K_server']
                # Derive AES key from K_server
                K = derive_key(K_server)             
                try:
                    # Decrypt the message
                    encrypted_data_with_nonce = base64.b64decode(data['data'])
                    decrypted_data = decrypt_with_key(K, encrypted_data_with_nonce, False)
                    decrypted_message = json.loads(decrypted_data.decode('utf-8'))
                    from_user = decrypted_message['from']
                    to_user = decrypted_message['to']
                    nonce_1 = decrypted_message['nonce_1']     
                                
                    # You should now have the decrypted message
                    print(f"{from_user} wants to send a message to {to_user}")

                    recipient_address = get_addr(to_user)
                    sender_address = get_addr(from_user)
                    if recipient_address not in users:
                        error_message = "User offline or cannot be reached. Try again later."
                        error_message_bytes = error_message.encode('utf-8')
                        encrypted_error_message = encrypt_with_key(K, error_message_bytes)
                        error_response = {"type": "user_offline", "message": base64.b64encode(encrypted_error_message).decode('utf-8')}                 
                        # Encrypt with the shared key
                        server_socket.sendto(json.dumps(error_response).encode('utf-8'), address)
                    else:

                    # Generate a new shared key between the two users
                        shared_key = generate_private_key()
                        K_to = users[recipient_address]['K_server']
                        K_to_bytes = derive_key(K_to)
                        ticket_to_B_contents = {
                            "shared_key": shared_key,
                            "from_user": from_user,
                            "sender_address": sender_address,
                        }
                        ticket_to_B_bytes = json.dumps(ticket_to_B_contents).encode('utf-8')
                        encrypted_ticket_to_B = encrypt_with_key(K_to_bytes, ticket_to_B_bytes)
                        ticket_to_B = base64.b64encode(encrypted_ticket_to_B).decode('utf-8')

                        # Encrypt the new shared key with the shared key between the server and the from user
                        message_content_to_A =  {
                            "nonce_1": nonce_1,
                            "shared_key": shared_key,
                            "to_address": recipient_address,
                            "ticket_to_B": ticket_to_B
                        }
                        message_bytes = json.dumps(message_content_to_A).encode('utf-8')
                        encrypted_message_contents = encrypt_with_key(K, message_bytes)
                        message_contents = base64.b64encode(encrypted_message_contents).decode('utf-8')
                        # Encrypt the new shared key with the shared key between the server and the to user for ticket to b                       
                        message = {
                            "type": "server_send",
                            "data": message_contents,
                        }
                        server_socket.sendto(json.dumps(message).encode('utf-8'), address)
                except InvalidTag as e:
                    print("Decryption failed: InvalidTag", e)
                except Exception as e:
                    print("An error occurred:", e)

if __name__ == '__main__':
    count = 0
    while count < 3:
        check = getpass.getpass("Enter Password: ")
        # verifying the hash of the password
        check = base64.b64encode(check.encode("utf-8"))
        check = str(check)
        check = base64.a85encode(check.encode("utf-8"))
        if check == b'@OG;[;KQ>K1d*2':
            print("You have successfully logged in as admin\n")

            parser = argparse.ArgumentParser(usage="./chat_server <-sp port>")
            parser.add_argument('-sp', type=int, required=False, dest='port')
            args = parser.parse_args()
            port = args.port

            js = {
                "host": "127.0.0.1",
                "port": port
            }

            config = json.dumps(js)

            with open('../server_config.json', 'w') as f:
                f.write(config)
            server_program(port)
        else:
            print("Incorrect try again")
            count += 1

    print("Too many incorrect attempts exiting...\n")