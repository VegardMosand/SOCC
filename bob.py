import socket
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

HOST = '127.0.0.1'
MAX_NUM_TWO_BYTES = 65536

def deserialize(bytes: bytes, counter: int):
    '''
    Returns a tuple of the message and signature contained in bytes.
    Exits if counter is not in order.
    bytes has to be in the following format
    |    2 bytes    |    2 bytes    |              |              |
    | Message length|  Counter      |   Message    |   Signature  |

        Parameters:
            bytes (bytes): Bytes containing message and signature
            counter (int): number increasing for each received message. Needs to be equal to the number in bytes

        Returns:
            tuple: tuple containing message and signature
    '''
    msgindex = int.from_bytes(bytes[0:2], 'big') + 4
    recv_counter = int.from_bytes(bytes[2:4], 'big')
    if (recv_counter != counter):
        print("Message not in order! Quitting..")
        sys.exit(0)
    return (bytes[4:msgindex], bytes[msgindex:])

def accept_connection():
    '''
    Accepts a connection on a user specified port and returns a socket representing the connection
    '''
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = int(input("Please specify an unused port number over 1024: "))
    try:
        soc.bind((HOST, port))
    except socket.error as message:
        print('Bind failed. Error Code : '
              + str(message[0]) + ' Message '
              + message[1])
        sys.exit(1)

    soc.listen(1)

    connection, _adress = soc.accept()
    return connection


def receive_message(connection: socket, private_key, counter: int):
    '''
    Waits for a message on connection, then decrypts and deserializes the message

        Parameters:
            connection (socket): socket to wait for message on
            private_key: private key to decrypt the message
            counter (int): counter to protect against replay attacks

        Returns:
            tuple: tuple containing message and signature
    '''
    var = connection.recv(1024)

    return deserialize(decrypt(var, private_key), counter)


def verify_signature(message, signature):
    '''
    Verifies signature using alice's public key. If the signature cant be verified an exeption is thrown
    '''
    with open("keys/a_pub.pub", "rb") as key_file:

        public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("Verified message is from A!")


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


def read_priv_key():
    '''
    Reads and returns private key (keys/b_priv) from file
    '''
    with open("keys/b_priv.pem", "rb") as key_file:

        return serialization.load_pem_private_key(

            key_file.read(),

            password=None,

        )


def main():
    connection = accept_connection()
    counter = 0
    while (True):
        private_key = read_priv_key()
        (message, signature) = receive_message(
            connection, private_key, counter)
        counter = (counter + 1) % MAX_NUM_TWO_BYTES 
        print(str(message))
        verify_signature(message, signature)

    connection.close()


main()
