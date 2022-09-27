import time
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime

HOST = '127.0.0.1'
PORT = 8595

def read_priv_key():
    with open("keys/a_priv.pem", "rb") as key_file:

        return serialization.load_pem_private_key(

            key_file.read(),

            password=None,

        )

def read_pub_key(path):
    with open(path, "rb") as key_file:

        return serialization.load_pem_public_key(

            key_file.read(),

        )

def event_loop(private_key, b_pub):
    print(message)
    s = socket.socket()
    s.connect((HOST, PORT))

    while(True):
        message=bytes(datetime.now().strftime("%d/%m/%Y, %H:%M:%S"), encoding='ascii')
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        payload = encrypt(serialize(message, signature), b_pub)
        packet = serialize(b'b', payload) 
        s.send(packet)
        time.sleep(2)
    s.close()

def encrypt(bytes : bytes, public_key):
    return public_key.encrypt(
        bytes,
        padding.OAEP(

            mgf=padding.MGF1(algorithm=hashes.SHA256()),

            algorithm=hashes.SHA256(),

            label=None

        )

    )

def serialize(message : bytes, signature : bytes) -> bytes:
    return len(message).to_bytes(2, 'big')+message+signature

def main():
    private_key = read_priv_key()
    b_pub = read_pub_key("keys/b_pub.pub")
    event_loop(private_key, b_pub)

main()