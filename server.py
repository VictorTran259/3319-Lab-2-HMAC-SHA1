import socket
import secrets
import sha1

# based on code provided on digitalocean.com
# link: https://www.digitalocean.com/community/tutorials/python-socket-programming-server-client

# get the host name
host = socket.gethostname()
port = 5000

server_socket = socket.socket() # get instance
# look closely. The bind() function takes tuple as argument
server_socket.bind((host,port)) # bind host address and port together

print("Server is running...\n")

# configure how many client the server can listen simultaneously
server_socket.listen(1)
conn, address = server_socket.accept()  # accept new connection
print("Accept new connection from " + str(address) + "...\n")

# open the txt file containing the password and store it in 'password'
with open("password.txt","r") as f:
    password = f.read()

# code for using the Random_number.txt file for the random number
# ***comment this code out and uncomment the code below it designated for generating random numbers if you want to use random number generation instead***
# open the txt file containing the random number and store it in 'rand_num'
with open("Random_number.txt","r") as f:
    rand_num = f.read()

# send the random number to the client
conn.send(rand_num.encode())

# calculate Si and store it in 'Si'.
Si = password.encode() + rand_num.encode()

# code for generating random numbers
# ***uncomment the lines of code below and comment the code using Random_number.txt if you would rather generate random numbers***
# generate a random 64-byte key
#generated_rand_num = secrets.token_bytes(64)

# send the random number to the client
#conn.send(generated_rand_num)

# calculate Si and store it in 'Si'.
#Si = password.encode() + generated_rand_num

# calculate the hash value of Si
Si_hash = sha1.sha1(Si)

while True:
    # take input from server side
    message = input("\nInput the message to be sent to the server: ")

    # server closes if the message 'exit' is the input
    if message.lower().strip() == 'exit':
        print("Server is closing...")
        break
    
    # send the server's message to the client
    conn.send(message.encode())

    # server receives the client's calculated HMAC
    client_So_hash = conn.recv(20)

    # convert the received bytes to a hexadecimal string
    client_So_hex = client_So_hash.hex()

    print("Received HMAC value from client:", client_So_hex)

    # server calculates So
    So = rand_num.encode() + bytes.fromhex(Si_hash)
    # ***uncomment this line of code below and comment the line above if using random number generation instead of Random_number.txt***
    #So = generated_rand_num + bytes.fromhex(Si_hash)

    # server calculates HMAC
    So_hash = sha1.sha1(So)

    print("Calculated HMAC value by server:", So_hash)

    # check for equivalency between the client's calculated HMAC and the server's calculated HMAC
    if client_So_hex == So_hash:
        print("The server calculated HMAC value and the client calculated HMAC value are identical. Authentication successful.")
    else:
        print("The server calculated HMAC value and the client calculated HMAC value are not identical. Authentication failed.")
    
server_socket.close()  # close the connection
