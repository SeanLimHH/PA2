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
                                read_bytes(client_socket, 8))
                            filename = read_bytes(
                                client_socket, filename_len).decode("utf-8")
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
                        
                        case 3: #* 8 bytes => 64 bits. First message should thus be 000...00101
                            #* Client sends 3 messages, so we must process it one-by-one.
                            #* First message just purely routes to this case; in a way; we can deal with the subsequent 2 messages:
                            #* Second message from client is the size of (message to be privately signed by csertificate) in bytes
                            
                            #* With these two messages (second and third), server must return 4 messages:
                            #* 1. Size of the next message in bytes
                            #* 2. Server-authenticated of the message
                            #* 3. Signature for 1.; signed by the server
                            #* 4. Signature for 2.; signed by the server
                            
                            #* So my solution is to:
                            #* a. Using client's second message, we have to reserve X amount of bytes;
                            #*    determined by the size for the next recv. This is done by the read_bytes() above.
                            #* b. The reserved amount of bytes is then interpreted as the message to be authenticated by the server; 
                            #*    sent by client. This is done by the read_bytes() above.
                            #* c. We will therefore extract b. out via the bytes reserved. 
                            #* d. Since this is the server, server-authenticate this message.
                            #*    This is server response second message.
                            #* e. Compute the authenticated message's size in bytes.
                            #*    This is server response first message.
                            #*    We need to know the size of the authenticated message to send back to client.
                            #* f. Using the private key server_private_key.pem, sign the authenticated message.
                            #*    This is server response third message.
                            #* g. Compute f's size in bytes.
                            #*    This is server response fourth message.
                            
                            print('MODE 3 sent by client. AP protocol initiated.')
                            
                            messageByteSize = convert_bytes_to_int(read_bytes(client_socket, 8))
                            print("From client, expect the next message to have byte size of:", messageByteSize)
                           
                            #* Third message from client is the actual (message to be privately signed by csertificate)
                            message = read_bytes(client_socket, messageByteSize)
                            print("message with nonce prepended:",message)
                            nonce = message[:8]
                            if nonce in usedNonces:
                                print("Nonce was used before!")
                                print("Closing connection...")
                                s.close()
                                break
                            else:
                                usedNonces.add(nonce)
                            
                            print("Used nonces:", usedNonces)
                            
                            print("From client, this message is:", message)
                            with open("./auth/_private_key.pem", "rb") as key_file: #* https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
                                private_key = serialization.load_pem_private_key(
                                    key_file.read(),
                                    password=None)
                                
                            serverAuthenticatedMessage = private_key.sign( #* https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
                                message,
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA256())
                            
                            print('Server authenticated message:', serverAuthenticatedMessage)
                            serverAuthenticatedMessageLength = len(serverAuthenticatedMessage)
                            print('Length of server authenticated message:', serverAuthenticatedMessageLength)
                            
                            with open("./auth/server_signed.crt", "rb") as fp:
                                fileData = fp.read()
                                
                            '''
                            print(convert_int_to_bytes(serverAuthenticatedMessageLength))
                            print(type(convert_int_to_bytes(serverAuthenticatedMessageLength)))
                            print(serverAuthenticatedMessage)
                            print(type(serverAuthenticatedMessage))
                            
                            print(convert_int_to_bytes(len(fileData)))
                            print(type(convert_int_to_bytes(len(fileData))))
                            print(fileData)
                            print(type(fileData))
                            '''
                            
                            client_socket.sendall(convert_int_to_bytes(serverAuthenticatedMessageLength))
                            print('First send passed')
                            client_socket.sendall(serverAuthenticatedMessage)
                            print('Second send passed')
                            client_socket.sendall(convert_int_to_bytes(len(fileData)))
                            print('Third send passed')
                            client_socket.sendall(fileData)
                            print('Fourth send passed')
                        
                            print("Note: I used a nonce to prevent replay attacks, this is the second requirement: to ensure that i am talking to a live server.")
                            print("The nonce is generated and prepended in my client message. This nonce is randomly generated and then the server will check if it is used before.")
                            print("An attack will thus be unable to proceed if the same nonce is used, since the server side rejects if the nonce was used before.")
                    
    except Exception as e:
        print(e)
        s.close()


if __name__ == "__main__":
    main(sys.argv[1:])
