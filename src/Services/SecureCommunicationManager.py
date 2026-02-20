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
    """
    Manages secure communication between a client and server using encryption and token-based
    authentication mechanisms. This class handles encryption key generation, data encryption,
    and data decryption, as well as validation and management of authentication tokens.

    The class is primarily designed to establish and maintain a secure communication channel
    by performing necessary encryption handshakes and data exchange in a secure manner.

    :ivar client: The client socket used for communication.
    :type client: socket.socket
    :ivar token_service: The service used to manage encryption tokens.
    :type token_service: TokenService
    :ivar master_aesgcm: The AES-GCM object initialized with the master key for encryption operations.
    :type master_aesgcm: AESGCM
    :ivar key: The symmetric encryption key used for encrypting and decrypting client data.
    :type key: bytes
    :ivar aesgcm: The AES-GCM object initialized with the symmetric encryption key.
    :type aesgcm: AESGCM
    :ivar token: The current authentication token in use for the communication session.
    :type token: bytes
    """
    def __init__(self, client: socket.socket, token_service: TokenService, master_key):
        """
        Initializes the instance of the class with required dependencies and cryptographic setup.

        This constructor sets up the required dependencies including a client for communication,
        a token service for handling authentication tokens, and cryptographic configurations
        using a master key for AES-GCM encryption. It does not initialize the derived key or
        AES-GCM cryptographic handler for derived keys at this stage, and ensures the token is
        initialized to an empty byte sequence.

        :param client: The socket client instance used for communication.
        :type client: socket.socket
        :param token_service: The service handling authentication tokens.
        :type token_service: TokenService
        :param master_key: The master key used for AES-GCM encryption setup.
        """
        self.client: socket.socket = client
        self.token_service = token_service
        self.master_aesgcm: AESGCM = AESGCM(master_key)
        self.key = None
        self.aesgcm = None
        self.token = b""

    def receive_data(self):
        """
        Handles the receiving of data over a client-server connection and processes the
        received data based on encryption-handshaking protocols.

        This method is responsible for managing a two-way encrypted communication
        between a client and server. It handles initial encryption handshaking,
        decrypting previously encrypted messages, and validation of encryption tokens.

        :raises SystemExit: If invalid token scenarios and retries fail.
        :raises ValueError: If the received data cannot be split as expected.
        :raises CryptoError: Raised during failures in encryption or decryption processes.

        :return: The decrypted message if applicable, or an error message string if an
            unrecognized flag or invalid data is received.
        :rtype: str or bytes
        """
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
        """
        Responds to a client by sending an encrypted message. If the current token needs refreshing, a new
        encryption token is generated before sending the message.

        :param message: The message to be sent to the client, provided as a byte sequence.
        :type message: bytes
        :return: None
        """
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
        """
        Encrypts the provided message using AES-GCM encryption and appends metadata such
        as a token, nonce, and encryption flags to the resulting message. If encryption
        is disabled or the message is empty, the original unencrypted message is returned
        with metadata.

        :param message: The message to be encrypted as raw bytes.
        :type message: bytes
        :param token: A unique identifier added to the message for context or authentication.
        :type token: bytes
        :param encryption_flag: A flag indicating the start of an encrypted message.
        :type encryption_flag: bytes
        :param encrypt_message: Indicates if the message should be encrypted. Defaults to True.
        :type encrypt_message: bool
        :return: The final encrypted message or the original message with metadata.
        :rtype: bytes
        """
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
        """
        Writes non-encrypted data by combining several byte components and returns the resulting message.

        The method constructs a binary message by concatenating the encryption flag, a token, and the
        provided message, separated by predefined encryption separators and finalized with an end flag.
        The constructed message is typically used for non-encrypted communication or data packaging.

        :param message:
            The primary binary message to be packaged.
        :param token:
            A binary token used for identification or authentication within the constructed message.
        :param encryption_flag:
            A binary flag indicating the encryption status of the data. Defaults to `resume_flag`.
        :return:
            A binary message constructed by combining the input parameters and separators.
        """
        message_to_return = bytes(encryption_flag) + bytes(encryption_separator) + bytes(token) + bytes(encryption_separator) + bytes(encryption_separator) + bytes(message) + bytes(end_flag)
        logging.debug(f"Non-encrypted message: {message_to_return}")
        return message_to_return