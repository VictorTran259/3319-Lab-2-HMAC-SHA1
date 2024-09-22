import socket
import sha1

# based on code provided on digitalocean.com
# link: https://www.digitalocean.com/community/tutorials/python-socket-programming-server-client

host = socket.gethostname() # as both code is running on same pc
port = 5000 # socket server port number

client_socket = socket.socket() # instantiate
client_socket.connect((host,port)) # connect to the server

# open the txt file containing the password and store it in 'password'
with open("password.txt","r") as f:
    password = f.read()

print("Successfully connected to server. Waiting for response from server...")

# client receives the random number from the server
server_rand_num = client_socket.recv(64)

print("Server has sent over the random number to the client.")

# calculate Si and store it in 'Si'.
Si = password.encode() + server_rand_num

# calculate the hash value of Si
Si_hash = sha1.sha1(Si)

while True:
    # client receives the message sent by the server
    server_message = client_socket.recv(64)

    # client will stop running once the server closes through an 'exit' input
    if not server_message:
        print("\nServer is closing. Disconnecting from server...")
        break

    print("\nReceived message from server:", server_message.decode())

    # client calculates So
    So = server_rand_num + bytes.fromhex(Si_hash)

    # client calculates HMAC
    So_hash = sha1.sha1(So)

    # convert the client's calculated HMAC to bytes and send it to the server
    client_So_bytes = bytes.fromhex(So_hash)
    client_socket.send(client_So_bytes)

    print("Calculated HMAC value by client:", So_hash)

client_socket.close() # close the connection