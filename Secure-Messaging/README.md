# Secure Messaging Application
Aishwarya Vinod, Mallory Gilligan

A project for CY4740 Network Security at Northeastern Univeristy

## Description

This application provides a cryptographically secure way to message your friends!
Simply sign in with your username/password (sorry members only 😉) and send any message your heart may desire to your bestest friends using send. Want to know who is online?
Just ask the program to list! The world is your oyster, and we're a messaging program!

## Installation

### Server Installation

1. Clone the repository: `git clone [https://github.com/gilliganmal/Secure-Messaging.git]`
2. Navigate to the server directory: `cd server`
3. Install dependencies: install the `cryptography` library with pip/brew/apt
4. Start the server: `./chat_server <-sp port>`

   -sp indicates the port you want the program to run on. the program automatically runs on the users localhost
   
6. Enter in server password
7. If sucessfully connected you will see `"Server Initialized..."` in your terminal interface

### Client Installation

1. Navigate to the client directory: `cd client`
2. Install dependencies: install the `cryptography` library with pip/brew/apt
3. Start the client: `./chat_client`
4. Enter in you username and password as prompted
5. If sucessfully connected you will see `"Log in successful!"` in your terminal interface

### Pre-Configured Users

- **Username**: bob | **Password**: P3bble_Cur5e
- **Username**: alice | **Password**: HarryPotter_203
- **Username**: aishu | **Password**: Ch*colate101
- **Username**: mallory | **Password**: chaRacTer.muLLed0



### Usage

The client application provides three main commands:

1. **list**: This command retrieves a list of online users.

   Example usage:
   ```
   list
   ```

2. **send**: This command is used to send a message or data.

   Example usage:
   ```
   send <user> <message>
   ```

   Replace `<user>` with the user you want to send your message to.
   
   Replace `<message>` with the content you want to send.

4. **exit**: This command terminates the client application and closes the connection to the server.

   Example usage:
   ```
   exit
   ```






