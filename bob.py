import socket
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
 
def deserialize(bytes : bytes):
    msglen = int.from_bytes(bytes[0:2], 'big')+2
    return (bytes[2:msglen], bytes[msglen:])

 
# specify Host and Port
HOST = '127.0.0.1'
PORT = 8591
def accept_connection():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        soc.bind((HOST, PORT))
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

def receive_message(connection : socket, private_key):
    var = connection.recv(1024)
    
    return deserialize(decrypt(var, private_key))

def verify_signature(message, signature):
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
    return key.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),

            algorithm=hashes.SHA256(),

            label=None
        )
)

def read_priv_key():
    with open("keys/b_priv.pem", "rb") as key_file:

        return serialization.load_pem_private_key(

            key_file.read(),

            password=None,

        )

def main():
    connection = accept_connection()
    while(True):
        private_key = read_priv_key()
        (message, signature) = receive_message(connection, private_key)
        print(str(message))
        verify_signature(message, signature)

    connection.close()
main()