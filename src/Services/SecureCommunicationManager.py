import logging
import socket
import sys
import time
from base64 import b64decode
from os import urandom

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from Dependencies import Constants
from Dependencies.Constants import buffer_size, end_flag, encryption_separator, resume_flag, init_flag
from Services.TokenService import TokenService


class SecureCommunicationManager:
    def __init__(self, client: socket.socket, token_service: TokenService, master_key):
        self.client: socket.socket = client
        self.token_service = token_service
        self.master_aesgcm: AESGCM = AESGCM(master_key)
        self.key = None
        self.aesgcm = None
        self.token = b""

    def receive_data(self):
        logging.debug("Initializing data receiving")
        received_data = b""
        counter = 0
        finished = False
        while not finished:
            data_chunk = self.client.recv(buffer_size)
            counter += 1
            if len(data_chunk) > 0 :logging.debug(f"Received data chunk ({len(data_chunk)}): {data_chunk[:10]}...{data_chunk[-10:]}")
            else:
                sys.stdout.write(".")
                time.sleep(1)
            received_data += data_chunk
            if received_data.endswith(end_flag) or (len(data_chunk) < buffer_size and len(received_data) > 0):
                received_data = received_data[:-len(end_flag)]
                finished = True
            if counter == 2: logging.debug(f"Received data: {received_data}")
        logging.debug(f"finished receiving data: {received_data[:25]}...{received_data[-25:]}")

        data_parts = received_data.split(encryption_separator)
        flag, self.token, nonce, encrypted_message = data_parts[0:4]
        logging.debug(f"\nFlag - {type(flag)}: {flag};\nToken - {type(self.token)}: {self.token};\nNonce - {type(nonce)}: {nonce};\nEncrypted Message - {type(encrypted_message)}: {encrypted_message}")
        match flag:
            case Constants.init_flag:
                logging.info("Starting encryption handshake")
                private_key = x25519.X25519PrivateKey.generate()
                public_key = private_key.public_key()

                client_public_key_bytes = encrypted_message
                client_public_key = serialization.load_pem_public_key(client_public_key_bytes)
                logging.debug(f"Client public key: {client_public_key_bytes}")

                shared_secret = private_key.exchange(client_public_key)

                self.key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"encryption key").derive(shared_secret)
                self.aesgcm = AESGCM(self.key)

                public_key_bytes = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

                token_key_nonce = urandom(12)
                encrypted_key = self.master_aesgcm.encrypt(token_key_nonce, self.key, None)
                self.token = self.token_service.create_encryption_token(encrypted_key=encrypted_key, nonce=token_key_nonce)
                message = self._write_non_encrypted_data(message=public_key_bytes, token=self.token, encryption_flag=init_flag)
                logging.debug(f"Sending message: {message}")
                self.client.sendall(message)
                return self.receive_data()

            case Constants.resume_flag:
                logging.info("Resuming with existing encryption key")
                if self.token_service.is_token_valid(self.token):
                    decoded_token = self.token_service.decode_token(self.token)
                    encrypted_key, key_nonce = b64decode(decoded_token["encrypted_key"]), b64decode(decoded_token["nonce"])
                    logging.debug(f"Encrypted key: {encrypted_key}, type: {type(encrypted_key)},\nkey nonce: {key_nonce}, type: {type(key_nonce)}")

                    try:
                        self.key = self.master_aesgcm.decrypt(key_nonce, encrypted_key, None)
                    except exceptions.InvalidTag:
                        logging.error("Invalid token key")
                        self.client.sendall(self._write_encrypted_data(message=b"", token=b"", encryption_flag=init_flag))
                        return self.receive_data()

                    self.aesgcm = AESGCM(self.key)
                    decrypted_message = self.aesgcm.decrypt(nonce, encrypted_message, None)
                    logging.debug(f"Decrypted message: {decrypted_message}")
                    return decrypted_message
                else:
                    logging.error("Invalid token. Sending initialization flag...")
                    self.client.sendall(self._write_encrypted_data(message=b"", token=b"", encryption_flag=init_flag))
                    return self.receive_data()
            case _:
                logging.error("Invalid flag received")
                return "ERROR"

    def respond_to_client(self, message: bytes):
        if self.token_service.token_needs_refreshing(self.token):
            token_key_nonce = urandom(12)
            self.token = self.token_service.create_encryption_token(encrypted_key=self.master_aesgcm.encrypt(token_key_nonce, self.key, None), nonce=token_key_nonce)
        message_to_send = self._write_encrypted_data(message=message, token=self.token)
        logging.debug(f"Sending message: {message_to_send}")
        self.client.sendall(message_to_send)
        logging.debug("Message sent\n\n\n\n")

    def _write_encrypted_data(
            self,
            message: bytes,
            token: bytes,
            encryption_flag: bytes = resume_flag,
            encrypt_message: bool = True
            ) -> bytes:
        nonce = urandom(12)
        encrypted_message = self.aesgcm.encrypt(nonce, message, None) if message != b"" and encrypt_message and self.aesgcm is not None else message
        message = encryption_flag + encryption_separator + token + encryption_separator + nonce + encryption_separator + encrypted_message + end_flag
        logging.debug(f"Encrypted message: {message}")
        return message

    def _write_non_encrypted_data(
            self,
            message: bytes,
            token: bytes,
            encryption_flag: bytes = resume_flag
            ) -> bytes:
        message_to_return = bytes(encryption_flag) + bytes(encryption_separator) + bytes(token) + bytes(encryption_separator) + bytes(encryption_separator) + bytes(message) + bytes(end_flag)
        logging.debug(f"Non-encrypted message: {message_to_return}")
        return message_to_return