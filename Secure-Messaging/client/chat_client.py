#!/usr/bin/env python3
import socket 
import json, base64
import sys
import select
import getpass
import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# setting path
sys.path.append('../')
# importing
from utils import *

list_mes = {'type': 'list'}
global messagetobesent
global recp_username
K = None # global variable to hold the derived shared key with server


# Function to send messages
def send_message(client_socket, server_address, message):
    client_socket.sendto(json.dumps(message).encode(), server_address)


# Assume p and g are constants known beforehand (this would be received securely pre-shared and stored in the real world)
# Correct assignment without a trailing comma
p = 19337410215242086483798041373320755781197913013396671104138850758738832889221128897246987014520121469738425040443020197891527517960888153382752698186934647144929168794414856969190816274153481896019497357479000007281537960899707944447623841187544522289030305003808765959810225141646095182502979030862830289576306682211822315044002000259127329457374685553083427447744840446151375545392353419523428209126529233779051746374587585914854404653535404055362122644052403260336419905926879730891357936468472158343374950180863994852556924091108498736188306974654530630422468968636554831219172718665922460134215553660360363374503
g = 2

# Global variable to hold the client's private key 'a'
client_private_key_a = None

user_communications = {} #dictionary to store the shared key between users

# Function to generate a random private key 'a' and calculate 'g^a mod p'
def generate_ga_mod_p(g, p):
    global client_private_key_a
    client_private_key_a = random.SystemRandom().randint(1, p-1)
    ga_mod_p = pow(g, client_private_key_a, p)
    return ga_mod_p

# Function to hash the password before the client computes the shared key (the server also does the same and this standard will be
# agreed upon by both the client and server)
def hash_user_password(password):
    # Password should be hashed and converted into an integer
    pw_bytes = password.encode('utf-8')
    pw_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    pw_hash.update(pw_bytes)
    W = int.from_bytes(pw_hash.finalize(), byteorder='big')
    return W


# K = g ^(b(a+uW))mod p 
def compute_client_shared_key(B, g, p, a, u, password):
    # Hash the password to get W
    W = hash_user_password(password)
    
    # Compute the exponent (a + uW) mod p
    exponent = (a + u * W) % p
    
    # Compute the shared key K
    K = pow(B, exponent, p)
    
    return K

# Function to handle 'send' command
def handle_send_command(to_username, K, client_socket, server_address):
    username = to_username
    user_communications.setdefault(username, {}) #to make sure that the sender keeps track of the recipient
    nonce_1 = random.randint(1, 99999999)  # Generate a random nonce
    global last_sent_nonce_1  # since we are using this variable outside this function
    last_sent_nonce_1 = nonce_1  # Store the last sent nonce for verification
    # Create the message dictionary
    message_dict = {
        'from': user,
        'to': username,
        'nonce_1': nonce_1
    }
    # Convert dictionary to JSON and encode to bytes
    message_bytes = json.dumps(message_dict).encode('utf-8')
    # Encrypt the message with the shared key
    encrypted_message = encrypt_with_key(K, message_bytes)
    # Create a message envelope
    send_message_dict = {
        'type': 'SEND',
        'data': base64.b64encode(encrypted_message).decode('utf-8')  # Encode encrypted data to base64 for transmission
    }
    # Send the encrypted message to the server
    send_message(client_socket, server_address, send_message_dict)


# gets the whole message as opposed to one word
def get_message(cmd):
    mes = ''
    length = len(cmd)
    start = 2
    while start < length:
        mes += cmd[start]
        mes += " "
        start = start + 1
    return mes

def client_program(host, port, user):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # instantiate
    server_add = (host, port)
    login = False

    try:
        password = getpass.getpass("Please enter your password: ")
        ga_mod_p = generate_ga_mod_p(g, p) #send only ga_mod_p to the server
        W = hash_user_password(password)  # Hash the password to get W

        # Send sign-in message to the server including username, g^a mod p, and the port and ip of the client
        mes = {"type": "SIGN-IN", "username": user,"g^amodp":ga_mod_p, 'port': port, 'ip': host}
        send_message(client_socket, server_add, mes)


        # While online
        while True:
            sockets_list = [sys.stdin, client_socket]
            read_sockets, _, _ = select.select(sockets_list, [], [], 10)  # monitor for read events with timeout
            if not read_sockets:
                # if server doesnt send check-in means it timed out
                print("No data received from the server. Exiting.")
                exit_message = {'type': 'exit', 'USERNAME': user}
                send_message(client_socket, server_add, exit_message)
                client_socket.close()
                sys.exit(0)

            # Start listenting
            for sock in read_sockets:
                if sock == client_socket:
                    data = sock.recv(65535).decode()  # receive response
                    if data:
                        response = json.loads(data)
                        # Inside client_program, after receiving the SRP_RESPONSE message
                        if response["type"] == "SRP_RESPONSE":
                            try:
                                # Parse the server's response
                                B_received = int(response["g^b+g^W_mod_p"])
                                u = int(response["u"])
                                c_1 = int(response["c_1"])
                                a = client_private_key_a

                                # Subtract g^W mod p from B received to get g^b mod p
                                gW_mod_p = pow(g, W, p)
                                B = (B_received - gW_mod_p + p) % p  # Add p to avoid negative result

                                # Now compute the shared key using the received values and the client's private 'a'
                                K_client = compute_client_shared_key(B, g, p, client_private_key_a, u, password)

                                #AES requires at least 16 bytes (128 bit) for the key, so we take the first 16 bytes of K_client          
                                K = derive_key(K_client) 
                                # Client side: converting c_1 to bytes before encryption
                                c_1_bytes = c_1.to_bytes((c_1.bit_length() + 7) // 8, 'big')
                                # Encrypt c_1 with the derived symmetric key
                                encrypted_c1 = encrypt_with_key(K, c_1_bytes)

                                # Generate a new nonce 'c_2'
                                c_2 = random.randint(1, 99999999)

                                # Prepare and send encrypted c_1 and c_2 to the server
                                auth_message = {
                                    "type": "AUTH_MESSAGE",
                                    "encrypted_c1": base64.b64encode(encrypted_c1).decode(),  # Include nonce with encrypted message
                                    "c_2": c_2,
                                }
                                send_message(client_socket, server_add, auth_message)

                            except Exception as e:
                                print("Error computing shared key:", e)

                        # Inside client_program, after receiving the AUTH_RESPONSE message
                        if response["type"] == "AUTH_RESPONSE":
                            # Decrypt encrypted_c2 received from server
                            encrypted_c2_base64 = response["encrypted_c2"]
                            encrypted_c2 = base64.b64decode(encrypted_c2_base64)

                            # verify user password and allow login
                            try:  
                                decrypted_c2 = decrypt_with_key(K, encrypted_c2, True)  # K is your derived key
                                decrypted_c2_int = int.from_bytes(decrypted_c2, byteorder='big')
                                
                                # Check if decrypted c_2 matches the one we sent
                                if decrypted_c2_int == c_2:
                                    login = True
                                    print("Log in successful!\nPlease enter command: ", end=' ', flush=True)
                                else:
                                    print("Server authentication failed")

                            except Exception as e:
                                print("Error decrypting c_2:", e)

                        # handle all the many errors that may arrise  
                        elif response["type"] == "error":
                            print(response["message"])
                            # some errors block loging back in, these allow for another try
                            if(response["login"]) == "yes":
                                    user = input("Please enter your username: ")
                                    client_program(host, port, user)
                            else:
                                exit(0)
                        elif response["type"] == "user_offline":
                            # Decrypt the message from the server
                            encrypted_data = base64.b64decode(response["message"])
                            decrypted_data = decrypt_with_key(K, encrypted_data, True)
                            print("\n<- " + decrypted_data.decode('utf-8'), "\nPlease enter command: ", end=' ', flush=True)
                        
                        # handle response from server after requesting to send
                        elif response["type"] == "server_send":
                            try:
                                encrypted_data_A = base64.b64decode(response["data"])
                                decrypted_data_A_bytes = decrypt_with_key(K, encrypted_data_A, True)
                                decrypted_data_A_str = decrypted_data_A_bytes.decode('utf-8')
                                decrypted_data_A = json.loads(decrypted_data_A_str)
                                recipient_address = decrypted_data_A["to_address"]
                                shared_key_AB = decrypted_data_A["shared_key"]
                                shared_key = derive_key(shared_key_AB)
                                verify_nonce_1 = decrypted_data_A["nonce_1"]

                                if verify_nonce_1 != last_sent_nonce_1:
                                    print("Nonce verification failed. Server cannot be trusted.")
                                    sys.exit(0)

                                data_to_be_sent_to_recipient = decrypted_data_A["ticket_to_B"]

                                # Convert recipient_address from list to tuple and use it
                                if recipient_address:
                                    recipient_tuple = (recipient_address[0], int(recipient_address[1]))  # Convert list to tuple and ensure port is an integer
                                    #for the sender to store info on the recipient
                                    nonce_2 = random.randint(1, 99999999)

                                    user_communications[to_username] = {
                                    'shared_key': shared_key,
                                    'address': recipient_tuple,
                                    'nonce_2': nonce_2
                                    }

                                    nonce_2_bytes = nonce_2.to_bytes((nonce_2.bit_length() + 7) // 8, 'big')
                                    encrypted_nonce_2 = encrypt_with_key(shared_key, nonce_2_bytes)

                                    whole_response = { "type": "shared_key",
                                                      "from_user": user,
                                                      "recipient_data": data_to_be_sent_to_recipient,
                                                      "nonce_2": base64.b64encode(encrypted_nonce_2).decode()
                                    }

                                    client_socket.sendto(json.dumps(whole_response).encode(), recipient_tuple)
                                else:
                                    print("Invalid recipient address")

                            except Exception as e:
                                print(f"Failed to process server_send data: {e}")
                        
                        # handles reciving a shared key from server for communications between clients
                        elif response["type"] == "shared_key": #recipient will receive this
                            encrypted_data = base64.b64decode(response["recipient_data"])
                            decrypted_data_bytes = decrypt_with_key(K, encrypted_data, True)
                            decrypted_data_B_str = decrypted_data_bytes.decode('utf-8')  # Convert bytes to string
                            decrypted_data = json.loads(decrypted_data_B_str)  # Parse string to JSON
                            shared_key_with_sender = decrypted_data["shared_key"]
                            shared_key = derive_key(shared_key_with_sender)
                            from_user = decrypted_data["from_user"]
                            user_communications[from_user] = {}
                            sender_address = decrypted_data["sender_address"]

                            sender_tuple = (sender_address[0], int(sender_address[1]))  # Convert list to tuple and ensure port is an integer                
                            encrypted_nonce_2 = base64.b64decode(response["nonce_2"])
                            decrypted_nonce_2_bytes = decrypt_with_key(shared_key, encrypted_nonce_2, True)
                            decrypted_nonce_2 = int.from_bytes(decrypted_nonce_2_bytes, byteorder='big')  # Parse string to JSON

                            nonce_2minus1 = decrypted_nonce_2 - 1
                            nonce_2minus1_bytes = nonce_2minus1.to_bytes((nonce_2minus1.bit_length() + 7) // 8, 'big')
                            nonce_3 = random.randint(1, 99999999)
                            nonce_3_bytes = nonce_3.to_bytes((nonce_3.bit_length() + 7) // 8, 'big')
                            nonce = {
                                "nonce_2minus1": base64.b64encode(nonce_2minus1_bytes).decode('utf-8'),  # Encode as base64 for JSON compatibility
                                "nonce_3": base64.b64encode(nonce_3_bytes).decode('utf-8'),
                            }
                            nonce_json = json.dumps(nonce)  # Serialize the dictionary into a JSON string
                            nonce_bytes = nonce_json.encode('utf-8')  # Encode the JSON string into bytes
                            encrypted_nonces = encrypt_with_key(shared_key, nonce_bytes)  # Now it's a bytes-like object
                            message = {
                                "type": "nonce_check_1",
                                "nonces": base64.b64encode(encrypted_nonces).decode('utf-8')  # Encode encrypted data to base64 for transmission
                            }
                            user_communications[from_user] = {
                                'shared_key': shared_key,
                                'address': sender_tuple,
                                'nonce_3': nonce_3
                            } #dictionary to store the shared key between users
                            client_socket.sendto(json.dumps(message).encode(), sender_tuple)

                        # nonce verification
                        elif response["type"] == "nonce_check_1":  # sender will receive this from the recipient
                            try:
                                encrypted_nonces = base64.b64decode(response['nonces'])
                                found_match = False

                                # Loop through user_communications to find which nonce_2 matches the nonce_2minus1 you received
                                for username, info in user_communications.items():
                                    if 'nonce_2' in info:
                                        shared_key = info['shared_key']
                                        decrypted_nonces_bytes = decrypt_with_key(shared_key, encrypted_nonces, True)
                                        # Decode bytes to string and load as JSON
                                        decrypted_nonces_str = decrypted_nonces_bytes.decode('utf-8')
                                        decrypted_nonces = json.loads(decrypted_nonces_str)
                                        nonce_2minus1 = int.from_bytes(base64.b64decode(decrypted_nonces['nonce_2minus1']), 'big')
                                        nonce_3 = int.from_bytes(base64.b64decode(decrypted_nonces['nonce_3']), 'big')
                                                                                
                                        if nonce_2minus1 == info['nonce_2'] - 1:
                                            from_user = username
                                            found_match = True
                                            break

                                if not found_match:
                                    print("Nonce mismatch")
                                    print("Please enter command: ", end=' ', flush=True)


                                # Correctly handling nonce_3
                                nonce_3minus1 = nonce_3 - 1
                                nonce_3minus1_bytes = nonce_3minus1.to_bytes((nonce_3minus1.bit_length() + 7) // 8, 'big')
                                nonce_3minus1_encrypted = encrypt_with_key(shared_key, nonce_3minus1_bytes)
                                message = {
                                    "type": "nonce_check_2",
                                    "nonce_3minus1": base64.b64encode(nonce_3minus1_encrypted).decode('utf-8')
                                }
                                recipient_address = user_communications[from_user]['address']
                                client_socket.sendto(json.dumps(message).encode(), recipient_address)
                                
                            except Exception as e:
                                print(f"Error processing nonce_check_1: {e}")
                                print("Please enter command: ", end=' ', flush=True)
        

                        #another nonce verification
                        elif response["type"] == "nonce_check_2":
                            try:
                                encrypted_nonce_3 = base64.b64decode(response['nonce_3minus1'])
                                found_match = False

                                # Loop through user_communications to find which nonce_3 matches the nonce_3minus1 you received
                                for username, info in user_communications.items():
                                    if 'nonce_3' in info:
                                        shared_key = info['shared_key']
                                        decrypted_nonce_3_bytes = decrypt_with_key(shared_key, encrypted_nonce_3, True)
                                        
                                        # Convert bytes directly to integer
                                        nonce_3minus1 = int.from_bytes(decrypted_nonce_3_bytes, 'big')
                                                                                
                                        if nonce_3minus1 == info['nonce_3'] - 1:
                                            found_match = True
                                            break
                                if not found_match:
                                    print("User verification failed. Nonce mismatch.")
                                    return                      
                                message = {
                                    "type": "authenticated"}
                                client_socket.sendto(json.dumps(message).encode(), user_communications[from_user]['address'])
                            except Exception as e:
                                print(f"Error processing nonce_check: {e}")
                                print("Please enter command: ", end=' ', flush=True)

                        # once communication is authenticated we can acutally send the message
                        elif response["type"] == "authenticated":
                            recp_address = user_communications[recp_username]['address']
                            receive_message = {
                                "type": "receive_message",
                                "message": messagetobesent,
                                "username": user,
                            }
                            send_message(client_socket, recp_address, receive_message)
                            print("Please enter command: ", end=' ', flush=True)
                        # read message sent
                        elif response["type"] == "receive_message":
                            from_user = response["username"]
                            print("\n<- From %s: %s" % (from_user, response["message"]))
                            print("Please enter command: ", end=' ', flush=True)
                        # if server shuts down                      
                        elif response["type"] == "GOODBYE":
                            print("\n" + response["message"])
                            print("\nExiting the client.")    
                            exit(0)                                 

            # After receiving data or handling input
            if login and (sock == sys.stdin):
                message = input().strip()
                if message:
                    cmd = message.split()
                    if cmd[0] == 'list':
                        send_message(client_socket, server_add, list_mes)  # send message
                        data = client_socket.recv(65535).decode()  # receive response
                        print("\n" + data, "\nPlease enter command: ", end='', flush=True)  # show in terminal
                    elif cmd[0] == 'send' and len(cmd) >= 3:
                        # Extract the username to send to and the message text
                        to_username = cmd[1]
                        recp_username = to_username
                        if recp_username == user:
                            print("You cant message yourself silly!")
                            print("\nPlease enter command: ", end=' ', flush=True)
                        else:
                            messagetobesent = get_message(cmd)
                            # Call the new function to handle the send command
                            handle_send_command(to_username, K, client_socket, server_add)
                    elif cmd[0] == 'exit':
                        exit_message = {'type': 'exit', 'USERNAME': user}
                        send_message(client_socket, server_add, exit_message)
                        print("\nExiting the client.")
                        client_socket.close()  # Close the socket
                        sys.exit(0)  # Exit the program
                    else:
                        print("<- Please enter a valid command either 'list' or 'send'")
                        print("Please enter command: ", end=' ', flush=True)
                        data = client_socket.recv(65535).decode()  # receive response
                sys.stdout.flush()  # flush the buffer to ensure immediate display

    except KeyboardInterrupt:
        exit_message = {'type': 'exit', 'USERNAME': user}
        send_message(client_socket, server_add, exit_message)
        print("\nExiting the client.")
        sys.exit(0)  # Ensure the client exits after sending the message

if __name__ == '__main__':
    sys.path.append('..')  # Add parent directory to Python path
    with open('../server_config.json', 'r') as f:
        config_data = json.load(f)
        host = config_data['host']
        port = int(config_data['port'])
    
    user = input("Please enter your username: ")

    client_program(host, port, user)