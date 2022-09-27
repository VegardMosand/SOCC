import socket
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
 
HOST = '127.0.0.1'
B_IP = '127.0.0.1'
A_PORT = 8595
B_PORT = 8591

def deserialize(bytes : bytes):
    msglen = int.from_bytes(bytes[0:2], 'big')+2
    return (bytes[2:msglen], bytes[msglen:])

def accept_connection():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        soc.bind((HOST, A_PORT))
    except socket.error as message:
        print('Bind failed. Error Code : '
            + str(message[0]) + ' Message '
            + message[1])
        sys.exit()

    soc.listen(1)

    connection, address = soc.accept()
    # print the address of connection
    print('Connected with ' + address[0] + ':'
        + str(address[1]))
    return connection 

def receive_message(connection : socket):
    var = connection.recv(1024)
    return deserialize(var)

def decrypt(cipher, key):
    return key.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
)

def main():
    connection = accept_connection()
    # TODO kobling mellom dest og ip/port
    
    s = socket.socket()
    s.connect((HOST, B_PORT))

    while(True):
        (dest, payload) = receive_message(connection)
        print(dest)
        print(payload)
        s.send(payload)
    connection.close()
    s.close()

main()