import time
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime

HOST = '127.0.0.1'
MAX_NUM_TWO_BYTES = 65536

def read_priv_key():
    '''
    Reads and returns private key (keys/a_priv) from file
    '''
    with open("keys/a_priv.pem", "rb") as key_file:

        return serialization.load_pem_private_key(

            key_file.read(),

            password=None,

        )


def read_pub_key(path):
    '''
    Reads and returns public key in path

    Returns:
        key_file (BufferedReader): Reader for public key
    '''
    with open(path, "rb") as key_file:

        return serialization.load_pem_public_key(

            key_file.read(),

        )


def event_loop(private_key, b_pub):
    '''
    Infinitly loops, sending a signed, encrypted timestamp every other second

    Parameters:
        private_key: own private key
        b_pub: Public key of recipient (b)
    '''
    s = socket.socket()
    port = int(input("Please specify an unused port number over 1024: "))
    s.connect((HOST, port))

    counter = 0

    while (True):
        message = bytes(datetime.now().strftime(
            "%d/%m/%Y, %H:%M:%S"), encoding='ascii')
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        payload = encrypt(serialize(message, signature, counter), b_pub)
        b = b'b'
        print(b, payload)
        packet = len(b'b').to_bytes(2, 'big') + b'b' + payload
        s.send(packet)
        counter = (counter + 1) % MAX_NUM_TWO_BYTES 
        time.sleep(2)
    s.close()


def encrypt(bytes: bytes, public_key):
    '''
    Encrypts and returns the data in bytes using public key

    Parameters:
        bytes: Bytes to encrypt
        public_key: Key to use for encryption

    Returns:
        ciphertext
    '''
    return public_key.encrypt(
        bytes,
        padding.OAEP(

            mgf=padding.MGF1(algorithm=hashes.SHA256()),

            algorithm=hashes.SHA256(),

            label=None

        )

    )


def serialize(message: bytes, signature: bytes, counter: int) -> bytes:
    '''
    Serializes the parameters into the following format:
    |    2 bytes    |    2 bytes    |              |              |
    | Message length|  Counter      |   Message    |   Signature  |

    Parameters:
        message: The message in bytes
        signature: The signature of the message
        counter: The current counter
    '''
    return len(message).to_bytes(2, 'big') + \
        counter.to_bytes(2, 'big') + message + signature


def main():
    private_key = read_priv_key()
    b_pub = read_pub_key("keys/b_pub.pub")
    event_loop(private_key, b_pub)


main()
