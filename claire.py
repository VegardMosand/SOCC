import socket
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

HOST = '127.0.0.1'
B_IP = '127.0.0.1'

def deserialize(bytes: bytes):
    '''
    Deserializes bytes into destination and payload

    Parameters:
        bytes: bytes to deserialize

    Returns:
        A tuple containing the destination and the payload
    '''
    msglen = int.from_bytes(bytes[0:2], 'big') + 2
    return (bytes[2:msglen], bytes[msglen:])


def accept_connection():
    '''
    Accepts a connection on a user specified port and returns a socket representing the connection
    '''
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = int(input("Please specify a port to communicate with Alice: "))
    try:
        soc.bind((HOST, port))
    except socket.error as message:
        print('Bind failed. Error Code : '
              + str(message[0]) + ' Message '
              + message[1])
        sys.exit()

    soc.listen(1)

    connection, _address = soc.accept()
    return connection


def receive_message(connection: socket):
    '''
    Waits for a message on connection, then deserializes and returns it

    Parameters:
        connection: socket to wait for message on

    Returns:
        A tuple containing the destination and the payload
    '''
    var = connection.recv(1024)
    return deserialize(var)


def decrypt(cipher, key):
    '''
    Decrypts cipher using key, returning the result.
    Throws an exception if decryption fails

    Parameters:
        cipher: ciphertext to decrypt
        key: key to use for decryption

    Returns:
        decrypted ciphertext
    '''
    return key.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def main():
    s = socket.socket()
    port = int(input("Please specify a port to communicate with Bob: "))
    connection = accept_connection()
    # TODO kobling mellom dest og ip/port
    s.connect((HOST, port))

    while (True):
        (dest, payload) = receive_message(connection)
        print(dest)
        print(payload)
        s.send(payload)
    connection.close()
    s.close()


main()
