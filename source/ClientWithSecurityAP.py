import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")

def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)

def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        while True:
            
            nonce = ''
            for i in range(8):
                nonce += str(secrets.randbelow(10))
            #* print("Generated nonce by client:", nonce)
            
            s.sendall(convert_int_to_bytes(3)) #* Send mode 3
            M2 = bytes((nonce + 'Client Request SecureStore ID').encode('utf-8'))
            M1 = convert_int_to_bytes(len(M2))
            s.sendall(M1)
            s.sendall(M2)
            
            #* Then here we expect to receive four messages from the server to check
            firstMessageLength = convert_bytes_to_int(read_bytes(s, 8))
            firstMessage =  read_bytes(s,firstMessageLength)
            secondMessageLength = convert_bytes_to_int(read_bytes(s, 8))
            secondMessage =  read_bytes(s,secondMessageLength)
            
            #* print('Response from server:')
            #* print('First message length:', firstMessageLength)
            #* print('First message:', firstMessage)
            #* print('Second message length:', secondMessageLength)
            #* print('Second message:', secondMessage)
            
            
            
            
            #* This is where we begin verifying the signature and certificates
            #* Verification of signature
            try:
                with open("auth/server_private_key.pem", mode="r", encoding="utf8") as key_file:
                    private_key = serialization.load_pem_private_key(
                        bytes(key_file.read(), encoding="utf8"), password=None
                    )
                public_key = private_key.public_key()
            except Exception as e:
                print(e)

            # Use private_key or public_key for encryption or decryption from now onwards
            try:
                public_key.verify(
                    firstMessage,
                    M2,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                # will continue here if the verify above passes
                
            except InvalidSignature:
                print('Signature failed to verify. Ending connection...')
                
                #* Then end connection
                s.sendall(convert_int_to_bytes(2))
                break
            
            
            
            #* Verification of certificate
            f = open("auth/cacsertificate.crt", "rb")
            ca_cert_raw = f.read()
            ca_cert = x509.load_pem_x509_certificate(
                data=ca_cert_raw, backend=default_backend()
            )
            ca_public_key = ca_cert.public_key()
            
            server_cert = x509.load_pem_x509_certificate(
                data=secondMessage, backend=default_backend()
            )
            try:
                ca_public_key.verify(
                    signature=server_cert.signature, # signature bytes to verify
                    data=server_cert.tbs_certificate_bytes, # certificate data bytes that was signed by CA
                    padding=padding.PKCS1v15(), # padding used by CA bot to sign the the server's csr
                    algorithm=server_cert.signature_hash_algorithm,
                )
            except InvalidSignature:
                print('Certificate failed to verify. Ending connection...')
                
                #* Then end connection
                s.sendall(convert_int_to_bytes(2))
                break
            
            #* Checking for validation of certificate
            assert server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after
            
            #* Note: I used a nonce to prevent replay attacks, this is the second requirement: to ensure that i am talking to a live server.
            #* The nonce is generated and prepended in my client message. This nonce is randomly generated and then the server will check if it is used before.
            #* An attack will thus be unable to proceed if the same nonce is used, since the server side rejects if the nonce was used before.

            filename = input(
                "Enter a filename to send (enter -1 to exit):"
            ).strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(data)))
                s.sendall(data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
