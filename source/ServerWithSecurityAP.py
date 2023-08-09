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
    address = args[1] if len(args) > 1 else "localhost"
    usedNonces = set()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(
                                client_socket, filename_len
                            ).decode("utf-8")
                            # print(filename)
                        case 1:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()

                            file_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            file_data = read_bytes(client_socket, file_len)
                            # print(file_data)

                            filename = "recv_" + filename.split("/")[-1]

                            # Write the file with 'recv_' prefix
                            with open(
                                f"recv_files/{filename}", mode="wb"
                            ) as fp:
                                fp.write(file_data)
                            print(
                                f"Finished receiving file in {(time.time() - start_time)}s!"
                            )
                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Closing connection...")
                            s.close()
                            break
                        
                        case 3:
                            #* Here we implement the AP
                            
                            #* This is the length of the next message to be received:
                            lengthOfMessage = convert_bytes_to_int(read_bytes(client_socket, 8))
                            #* This is the message to sign:
                            message = read_bytes(client_socket, lengthOfMessage)
                            nonce = message[:8]
                            if nonce in usedNonces:
                                print("Nonce was used before!")
                                print("Closing connection...")
                                s.close()
                                break
                            else:
                                usedNonces.add(nonce)
                            
                            try:
                                with open("auth/server_private_key.pem", mode="r", encoding="utf8") as key_file:
                                    private_key = serialization.load_pem_private_key(
                                        bytes(key_file.read(), encoding="utf8"), password=None)
                            except Exception as e:
                                print(e)

                            #* print('Length of message:',lengthOfMessage)
                            #* print('Message:',message)
                            #* print('Nonce:', nonce)
                            
                            # Use private_key or public_key for encryption or decryption from now onwards
                    
                            signedMessage = private_key.sign(
                                    message, # message in bytes format
                                    padding.PSS(
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH,),
                                    hashes.SHA256())
                            lengthOfSignedMessage = convert_int_to_bytes(len(signedMessage))
                                
                            with open("auth/server_signed.crt", "rb") as f:
                                serverSignedCertificate = f.read()
                            lengthOfServerSignedCertificate = convert_int_to_bytes(len(serverSignedCertificate))
                            
                            #* print('Length signed message', lengthOfSignedMessage)
                            #* print('Signed message', signedMessage)
                            #* print('serverSignedCertificate:', serverSignedCertificate)
                            #* print('Length of server signed certificate:',lengthOfServerSignedCertificate)
                            #* print('Server signed certificate:',serverSignedCertificate)
                            client_socket.sendall(lengthOfSignedMessage)
                            client_socket.sendall(signedMessage)
                            client_socket.sendall(lengthOfServerSignedCertificate)
                            client_socket.sendall(serverSignedCertificate)
                            
                            #* Note: I used a nonce to prevent replay attacks, this is the second requirement: to ensure that i am talking to a live server.
                            #* The nonce is generated and prepended in my client message. This nonce is randomly generated and then the server will check if it is used before.
                            #* An attack will thus be unable to proceed if the same nonce is used, since the server side rejects if the nonce was used before.
                    
    except Exception as e:
        print(e)
        s.close()


if __name__ == "__main__":
    main(sys.argv[1:])
