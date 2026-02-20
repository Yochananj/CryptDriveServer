import atexit
import json
import logging
import socket
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from Dependencies.Constants import *
from Dependencies.VerbDictionary import Verbs
from Services.SecureCommunicationManager import SecureCommunicationManager
from Services.ServerFileService import FileService, Items
from Services.TokenService import TokenService
from Services.UsersService import UsersService


class ServerClass:
    """
    Provides a server class to manage client-server communication and operations
    such as file management, user authentication, and secure communication.

    This class is responsible for setting up a server, listening to incoming client
    connections, and handling various client requests. It incorporates token-based
    authentication and encrypted communication for secure operations using helper
    services.

    :ivar server: The socket object used for server communication.
    :type server: socket.socket
    :ivar is_server_running: A flag indicating if the server is running.
    :type is_server_running: bool
    :ivar users_service: A service for managing user-related operations, such as
        authentication and user data.
    :type users_service: UsersService
    :ivar file_service: A service for managing file-related operations, such as
        file creation, deletion, and retrieval.
    :type file_service: FileService
    :ivar token_service: A service for handling token-based authentication and
        validation.
    :type token_service: TokenService
    :ivar encryption_token_master_key: The master encryption key for managing
        secured tokens.
    :type encryption_token_master_key: bytes
    :ivar host_addr: The server's host address for binding and communication.
    :type host_addr: Any
    :ivar pool: A thread pool executor to handle concurrent client connections
        efficiently.
    :type pool: ThreadPoolExecutor
    """
    def __init__(self):
        """
        Initializes the server object, configures necessary services, establishes a socket
        connection for client-server communication, and prepares multithreading for
        handling simultaneous tasks.

        Raises:
            OSError: If the server fails to bind to the specified address.
        """
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_server_running = False

        self.users_service = UsersService()
        self.file_service = FileService(self.users_service)

        self.token_service = TokenService()
        self.encryption_token_master_key = AESGCM.generate_key(bit_length=256)
        logging.debug(f"Generated token master key: {self.encryption_token_master_key}")

        self.host_addr = host_addr

        try:
            self.server.bind(self.host_addr)
            self.is_server_running = True
        except OSError as exception:
            logging.error(f"\n\n\nError starting server: {exception}")
            self.server_close()
            logging.info("Server Closed.")
            return

        self.pool = ThreadPoolExecutor(2*os.cpu_count())

        self._server_listen()

    def server_close(self):
        """
        Shuts down the server and performs cleanup operations.

        Closes the server, ensures the associated database connection is properly
        closed, and updates the server's running status to indicate it is no
        longer running.

        :return: None
        """
        self.server.close()
        self.file_service.close_db()
        self.is_server_running = False

    def _server_listen(self):
        """
        Starts the server to listen for incoming client connections. This method
        handles the client connections asynchronously using a thread pool. The
        server will continue running until terminated manually or due to an
        exception. Ensures the server is properly closed in case of interruptions.

        :return: None
        """
        try:
            self.server.listen(100)
            logging.info(f"Server listening On: {self.host_addr}")
            while self.is_server_running:
                client, client_addr = self.server.accept()
                logging.info(f"\n\n\n\nClient Connected: {client_addr}")
                self.pool.submit(self._begin_client_communication, client, client_addr)
        except KeyboardInterrupt:
            self.server_close()
        finally:
            self.server_close()
            logging.info("Server Closed.")

    def _begin_client_communication(self, client, client_addr):
        """
        Begins communication with a connected client. This method establishes secure
        communication with the client, receives their message, and processes it by
        parsing the message data.

        :param client: The socket object representing the client connection.
        :param client_addr: The address of the connected client as a tuple (IP, port).
        :return: None
        """
        logging.info(f"Receiving Message From: {client_addr}")
        secure_communication_manager = SecureCommunicationManager(client, self.token_service, self.encryption_token_master_key)
        message = secure_communication_manager.receive_data().decode()
        logging.info(f"Message Received: {message}. Parsing Message...")
        self._parse_message(message, secure_communication_manager)

    def _parse_message(self, message, secure_communication_manager: SecureCommunicationManager):
        """
        Parses an incoming message and processes it through a series of actions, including
        data extraction, token validation, action handling, and response generation.

        This method is responsible for managing the workflow of request handling, including
        logging details for debugging. It integrates with a secure communication manager to
        finalize the processing of responses.

        :param message: The incoming message to be parsed and processed.
        :type message: str
        :param secure_communication_manager: The secure communication manager responsible for sending
            processed responses securely.
        :type secure_communication_manager: SecureCommunicationManager
        :return: None
        """
        client_token, data, verb = self._get_data_from_request(message)

        logging.debug(f"Verb: {verb}, Token: {client_token},\n Data: {data}")

        client_token, is_token_valid, username = self._handle_token(client_token)

        needs_file_contents, response, response_data = self._handle_action(client_token, data, is_token_valid, username, verb)

        self._handle_response(client_token, data, needs_file_contents, response, response_data, secure_communication_manager, username)

    def _handle_response(self, client_token, data, needs_file_contents, response, response_data,  secure_communication_manager: SecureCommunicationManager, username):
        """
        Handles the communication response flow, including encoding, logging, sending, and conditionally receiving data
        based on the specified parameters. This function is responsible for orchestrating the response-handling logic
        necessary for secure communication.

        :param client_token: The unique identifier representing the client interaction within the communication session.
        :param data: Data object or payload associated with the communication that needs to be processed.
        :param needs_file_contents: Boolean flag to indicate if additional file contents need to be retrieved
            during the response handling phase.
        :param response: The response data in its initial unencoded state, which will be processed.
        :param response_data: Additional information or metadata associated with the response, often used for logging
            or tracking purposes.
        :param secure_communication_manager: Instance of the SecureCommunicationManager responsible for facilitating
            secure interactions between the client and the system, including sending and receiving data securely.
        :param username: The identifier or username of the client/user involved in the communication.
        :return: This function does not return any value.
        """
        self._log_response_details(response, response_data)

        response = response.encode()

        self._send_initial_response(response, response_data, secure_communication_manager)

        self._receive_data_if_needed(client_token, data, needs_file_contents, secure_communication_manager, username)

    def _get_data_from_request(self, message) -> Any:
        """
        Parses a message from a client request, extracts key components, and processes
        encoded data. Specifically, the function splits the input message, extracts
        tokens and input data, and decodes data into the appropriate formats, returning
        a structured result.

        :param message: The client request message formatted as a string containing
            a verb, client token, and encoded data.
        :type message: str
        :return: A tuple containing the client token, a list of processed data,
            and the request verb.
        :rtype: Tuple[str, List[Any], str]
        """
        message_parts = message.split(separator)
        logging.debug(f"Message parts: {message_parts}")
        verb = message_parts[0]
        client_token = message_parts[1]
        encoded_data = json.loads(message_parts[2])
        data = []
        for i in range(len(encoded_data)):
            item = encoded_data[i]
            if item[1] == "str":
                item = item[0]
            elif item[1] == "bytes":
                item = b64decode(item[0])
            data.append(item)

        return client_token, data, verb

    def _handle_token(self, client_token) -> Any:
        """
        Handles the processing of the provided client token, ensuring its validity
        and potentially refreshing it. This method retrieves the username from the
        token if it is valid and performs necessary checks for token refreshment.

        :param client_token: The client token that needs to be validated and processed.
                             Represents the authentication token of the client.
        :type client_token: str
        :return: A tuple containing the possibly refreshed client token, a boolean
                 indicating whether the token was valid, and the username extracted
                 from the token if it was valid.
        :rtype: tuple[str, bool, str]
        """
        is_token_valid = self.token_service.is_token_valid(client_token)

        username = ""
        if is_token_valid:
            username = self.token_service.decode_token(client_token)["username"]
            if self.token_service.token_needs_refreshing(client_token):
                client_token = self.token_service.create_login_token(
                    username=self.token_service.decode_token(client_token)["username"])

        logging.info(f"Is token valid: {is_token_valid}.")
        return client_token, is_token_valid, username

    def _send_initial_response(self, response, response_data, secure_communication_manager: SecureCommunicationManager):
        """
        Sends the initial response to the client through the secure communication manager.
        This method processes the provided response and response data, appending appropriate
        flags depending on their type (string or byte) before sending the message.

        :param response: The base response data to be sent to the client.
        :type response: bytes
        :param response_data: Additional data to be appended to the response. Can be either a
            string or bytes.
        :type response_data: str | bytes
        :param secure_communication_manager: The secure communication manager responsible for
            sending the processed response to the client.
        :type secure_communication_manager: SecureCommunicationManager
        :return: None
        """
        if len(response_data) > 0:
            logging.debug("Adding data to response")
            if isinstance(response_data, str):
                response += string_data_flag + response_data.encode()
            else:
                response += byte_data_flag + response_data
            logging.debug(f"Message with data: {response}")

        secure_communication_manager.respond_to_client(response)

    def _receive_data_if_needed(self, client_token, data, needs_file_contents, secure_communication_manager: SecureCommunicationManager, username):
        """
        Handles receiving data if needed and performs the file creation process. It waits for the file contents
        to be received when `needs_file_contents` is True and interacts with the file service accordingly to
        create a file for the user.

        :param client_token: Token used to identify the client and their session.
        :param data: List of data containing at least the file path, file name, and a nonce for security purposes.
        :param needs_file_contents: Indicates whether file contents need to be received before proceeding.
        :param secure_communication_manager: Instance of SecureCommunicationManager responsible for secure data
            transmission and client-server communication.
        :param username: Name of the user attempting the file creation process.
        :return: None
        """
        file_path, file_name, nonce = data[0:3]
        if needs_file_contents:
            logging.debug("Waiting for Data")
            encrypted_file_contents = secure_communication_manager.receive_data()
            if self.file_service.create_file(username, file_path, file_name, encrypted_file_contents, nonce):
                secure_communication_manager.respond_to_client(
                    self._write_message("SUCCESS", client_token, "FILE_CREATED").encode())
            else:
                secure_communication_manager.respond_to_client(
                    self._write_message("ERROR", client_token, "FILE_NOT_CREATED").encode())

    def _log_response_details(self, response, response_data):
        """
        Logs detailed information about the response and associated response data.

        This method writes debug-level logs for the provided response object, the
        response data content, and its associated metadata such as length and type.

        :param response: The response object containing details of the operation.
        :type response: Any
        :param response_data: The response content whose details, such as length and type, are logged.
        :type response_data: Any
        :return: None
        """
        logging.debug(f"Response: {response}")
        logging.debug(f"Response Data: {response_data}")
        logging.debug(f"Response Data Length: {len(response_data)}, type: {type(response_data)}")

    def _handle_action(self, client_token, data, is_token_valid, username,verb) -> Any:
        """
        Handles different user actions based on the specified verb. Each action corresponds
        to a specific functionality such as file operations, user authentication, or account
        management. The function interacts with helper private methods to execute the required
        operation and returns the result.

        :param client_token: The token used to authenticate the client making the request.
        :param data: The data payload associated with the action being performed.
        :param is_token_valid: Indicates whether the client token has been validated successfully.
        :param username: The username of the client performing the action.
        :param verb: Specifies the action to be performed, represented as a string from the Verbs enum.
        :return: A tuple containing three values:
            - needs_file_contents (bool): Indicates if the response requires file contents.
            - response (str): The outcome or status of the action performed.
            - response_data (Any): Additional data related to the response, if applicable.
        """
        response = ""
        response_data = ""
        needs_file_contents = False

        match verb:
            case Verbs.SIGN_UP.value:
                response = self._sign_up(client_token, data)

            case Verbs.LOG_IN.value:
                response = self._login(client_token, data)

            case Verbs.DOWNLOAD_FILE.value:
                response, response_data = self._download_file(client_token, data, is_token_valid,response_data, username)

            case Verbs.GET_ITEMS_LIST.value:
                response, response_data = self._get_items_list(client_token, data, is_token_valid, response_data, username)

            case Verbs.CREATE_FILE.value:
                needs_file_contents, response = self._create_file(client_token, data, is_token_valid,  needs_file_contents, username)

            case Verbs.DELETE_FILE.value:
                response = self._delete_file(client_token, data, is_token_valid, username)

            case Verbs.CREATE_DIR.value:
                response = self._create_dir(client_token, data, is_token_valid, username)

            case Verbs.DELETE_DIR.value:
                response = self._delete_dir(client_token, data, is_token_valid, username)

            case Verbs.RENAME_FILE.value:
                response = self._rename_file(client_token, data, is_token_valid, username)

            case Verbs.RENAME_DIR.value:
                response = self._rename_dir(client_token, data, is_token_valid, username)

            case Verbs.MOVE_FILE.value:
                response = self._move_file(client_token, data, is_token_valid, username)

            case Verbs.MOVE_DIR.value:
                response = self._move_dir(client_token, data, is_token_valid, username)

            case Verbs.CHANGE_USERNAME.value:
                response = self._change_username(client_token, data, is_token_valid, username)

            case Verbs.CHANGE_PASSWORD.value:
                response = self._change_password(client_token, data, is_token_valid, username)

            case _:
                logging.debug("Invalid Verb")
                response = self._write_message("ERROR", client_token, "INVALID_VERB")
        return needs_file_contents, response, response_data

    def _move_dir(self, client_token, data, is_token_valid, username) -> Any:
        """
        Moves a directory from one location to another using the provided data and user authentication token.

        :param client_token: The client authentication token used for validating the request.
        :type client_token: str
        :param data: A list containing the source directory path, target directory path, and directory name.
        :type data: list
        :param is_token_valid: A boolean flag indicating whether the provided authentication token is valid.
        :type is_token_valid: bool
        :param username: The username of the client performing the directory move operation.
        :type username: str
        :return: A response message indicating the success or failure of the directory move operation.
        :rtype: Any
        """
        if is_token_valid:
            if self.file_service.move_dir(username, data[0], data[1], data[2]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "DIR_NOT_FOUND_OR_ALREADY_EXISTS")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _move_file(self, client_token, data, is_token_valid, username) -> Any:
        """
        Moves a file from one location to another based on the provided parameters.

        This function handles file movement for the user specified by the username.
        It ensures the validity of the provided token, and if valid, attempts to move
        the file. If the operation is successful, it returns a success response;
        otherwise, it provides an appropriate error message.

        :param client_token: The token associated with the client making the request.
        :type client_token: str
        :param data: A list containing file operation details. It includes the source
            path, destination path, and file name.
        :type data: list[str]
        :param is_token_valid: A flag indicating whether the given client token is valid.
        :type is_token_valid: bool
        :param username: The username of the client requesting the operation.
        :type username: str
        :return: The response message indicating the success or failure of the operation.
        :rtype: Any
        """
        if is_token_valid:
            if self.file_service.move_file(username, data[0], data[1], data[2]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "FILE_NOT_FOUND_OR_ALREADY_EXISTS")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _rename_dir(self, client_token, data, is_token_valid, username) -> Any:
        """
        Renames a directory for a given user if the provided token is valid and
        the directory exists. If the token is invalid or the directory operation
        fails, an error message is returned.

        :param client_token: The token identifying the client making the request
        :param data: A list containing directory path information.
            - data[0]: Current directory path
            - data[1]: New directory name
            - data[2]: Target directory destination path
        :param is_token_valid: Boolean indicating whether the provided client token
            is valid
        :param username: The username of the client requesting the directory rename
        :return: A response message indicating the success or failure of the
            directory rename operation
        """
        if is_token_valid:
            if self.file_service.rename_dir(username, data[0], data[1], data[2]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "DIR_NOT_FOUND_OR_ALREADY_EXISTS")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _rename_file(self, client_token, data, is_token_valid, username) -> Any:
        """
        Attempts to rename a file on behalf of the user. If the provided token is valid,
        and the rename operation is successful, a success response is returned.
        Otherwise, an error response is generated detailing the reason for failure.

        :param client_token: Token associated with the client performing the operation.
        :type client_token: str
        :param data: A collection containing the filename to rename, the new filename,
                     and additional relevant details required by the operation.
        :type data: List[str]
        :param is_token_valid: Flag indicating whether the provided token is valid.
        :type is_token_valid: bool
        :param username: Name of the user requesting the rename operation.
        :type username: str
        :return: If the token is valid and the rename operation is successful, a success
                 response is returned. Otherwise, an error response indicating the reason for
                 failure is returned.
        :rtype: Any
        """
        if is_token_valid:
            if self.file_service.rename_file(username, data[0], data[1], data[2]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "FILE_NOT_FOUND_OR_ALREADY_EXISTS")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _delete_dir(self, client_token, data, is_token_valid, username) -> Any:
        """
        Deletes a directory if the user has a valid token and the directory exists.

        :param client_token: An arbitrary token associated with the client's session.
        :type client_token: str
        :param data: A list containing directory-related data. The exact structure of the list
            is expected to correspond with directory details such as its path.
        :type data: list
        :param is_token_valid: A boolean indicating whether the provided token is valid.
        :type is_token_valid: bool
        :param username: The username of the client attempting the directory operation.
        :type username: str
        :return: A response message indicating the success or error state of the operation.
        :rtype: Any
        """
        logging.debug("verb = DELETE_DIR")
        if is_token_valid:
            if self.file_service.delete_dir(username, data[0], data[1]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "DIR_NOT_FOUND")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _create_dir(self, client_token, data, is_token_valid, username) -> Any:
        """
        Creates a directory for a user if the provided token is valid, and the directory does not already exist.

        :param client_token: The token provided by the client to authenticate the request.
        :type client_token: str
        :param data: A list containing the name and path of the directory to be created.
        :type data: list
        :param is_token_valid: A boolean flag indicating whether the provided token is valid.
        :type is_token_valid: bool
        :param username: The username of the client requesting the directory creation.
        :type username: str
        :return: A response message indicating the success or failure of the directory creation process.
        :rtype: Any
        """
        if is_token_valid:
            if self.file_service.create_dir(username, data[0], data[1]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "DIR_EXISTS")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _delete_file(self, client_token, data, is_token_valid, username) -> Any:
        """
        Deletes a file associated with the given data and username based on the provided
        client token, ensuring the token validity.

        :param client_token: The unique token associated with the client making the request.
        :param data: A list containing file identification details.
        :param is_token_valid: A boolean flag indicating if the provided token is valid.
        :param username: The username associated with the file to be deleted.
        :return: A response indicating the result of the delete operation, which could be
                 a success message or an error message.
        """
        logging.debug("verb = DELETE_FILE")
        if is_token_valid:
            if self.file_service.delete_file(username, data[0], data[1]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "FILE_NOT_FOUND")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _create_file(self, client_token, data, is_token_valid, needs_file_contents, username) -> Any:
        """
        Creates a new file based on the provided parameters and input validation.

        This method attempts to create a new file in a specified path and filename if the
        authorization token is valid and the creation conditions are met. It determines if
        additional file data is required and constructs a response to indicate the outcome of the
        operation.

        :param client_token: The token used for authentication of the client request.
        :type client_token: str
        :param data: A tuple containing the file path and file name for the new file.
        :type data: tuple[str, str]
        :param is_token_valid: Boolean value indicating if the provided client token is valid.
        :type is_token_valid: bool
        :param needs_file_contents: A flag indicating whether additional file data (contents)
                                     will be required.
        :type needs_file_contents: bool
        :param username: The username of the client attempting the file creation operation.
        :type username: str
        :return: A tuple where the first element is a boolean indicating if file contents are
                 needed, and the second element is a response message providing information
                 about the outcome of the operation.
        :rtype: tuple[bool, str]
        """
        logging.debug("verb = CREATE_FILE")
        file_path, file_name = data[0:2]
        if is_token_valid:
            if self.file_service.can_create_file(username, file_path, file_name):
                response = self._write_message("SUCCESS", client_token, "READY_FOR_DATA")
                needs_file_contents = True
            else:
                response = self._write_message("ERROR", client_token, "FILE_EXISTS")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return needs_file_contents, response

    def _get_items_list(self, client_token, data, is_token_valid, response_data, username) -> Any:
        """
        Retrieves a list of directories and files based on the provided path for the given username.

        This method interacts with the `file_service` to fetch directories and files available
        in the specified path associated with the username. If a valid client token is provided,
        it serializes and includes the retrieved lists in the response. Otherwise, it returns
        an error response indicating an invalid token.

        :param client_token: Authentication token provided by the client.
        :param data: A list of input data where the first element is the target path.
        :param is_token_valid: Boolean flag to indicate whether the provided token is valid.
        :param response_data: Serialized response data containing directories and files.
        :param username: The username associated with the directories and files to be retrieved.
        :return: A tuple containing the response as a string and the serialized response data.

        """
        logging.debug("verb = GET_FILES_LIST")
        if is_token_valid:
            dirs = self.file_service.get_dirs_list_for_path(username, data[0])
            logging.debug(f"dirs: {dirs}")
            files = self.file_service.get_files_list_in_path(username, data[0])
            logging.debug(f"files: {files}")
            dirs_dumps = json.dumps([directory.__dict__ for directory in dirs])
            files_dumps = json.dumps([file_obj.__dict__ for file_obj in files])
            logging.debug(f"Response data: \n Dirs: {dirs_dumps} \n Files: {files_dumps}")
            response = self._write_message("SUCCESS", client_token, "SENDING_DATA")
            response_data = json.dumps(Items(dirs_dumps, files_dumps).__dict__)
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response, response_data

    def _download_file(self, client_token, data, is_token_valid, response_data, username) -> Any:
        """
        Downloads a file by retrieving its encrypted contents and associated nonce. It validates the
        provided client token and responds differently based on its validity.

        :param client_token: The token provided by the client for authentication purposes.
        :type client_token: str
        :param data: A list containing the file path and file name to be downloaded.
        :type data: list
        :param is_token_valid: A flag indicating whether the client token is valid or not.
        :type is_token_valid: bool
        :param response_data: The variable to be updated with the encrypted file contents.
        :type response_data: str or bytes
        :param username: The username of the client requesting the file download.
        :type username: str
        :return: A tuple containing the response message and the response data after processing.
        :rtype: tuple
        """
        logging.debug("verb = DOWNLOAD_FILE")
        if is_token_valid:
            path, file_name = data[0], data[1]
            encrypted_file_contents, nonce = self.file_service.get_file_contents_and_nonce(username, path, file_name)
            response_data = encrypted_file_contents
            logging.debug(f"Nonce: {nonce}")
            response = self._write_message("SUCCESS", client_token, b64encode(nonce).decode())
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response, response_data

    def _login(self, client_token, data) -> Any:
        """
        Authenticates a user by verifying the provided credentials, generating a login token,
        and retrieving user-related encrypted keys if the credentials are valid. If the
        credentials are not valid, it returns an error message.

        :param client_token: A token that represents the current client session.
        :param data: A list containing the username and corresponding password hash of the
            user attempting to log in.
        :return: A response message which includes the status of the login operation,
            a generated login token in case of successful authentication, and additional
            encrypted user keys. In case of failure, an error message is returned.
        """
        logging.debug("verb = LOG_IN")
        username, password_hash = data[0], data[1]
        if self.users_service.login(username, password_hash):
            derived_key_salt, encrypted_master_key, encrypted_master_key_nonce = self.users_service.get_user_derived_key_salt_and_encrypted_master_key_and_nonce(username)
            logging.debug(f"Derived Key Salt: {derived_key_salt},\nEncrypted Master Key: {encrypted_master_key},\nEncrypted Master Key Nonce: {encrypted_master_key_nonce}")
            user_keys_data_string = json.dumps(
                {"salt": b64encode(derived_key_salt).decode(),
                 "encrypted_file_master_key": b64encode(encrypted_master_key).decode(),
                 "nonce": b64encode(encrypted_master_key_nonce).decode()
                 }
            )
            response = self._write_message("SUCCESS", self.token_service.create_login_token(username), user_keys_data_string)
        else:
            response = self._write_message("ERROR", client_token, "INVALID_CREDENTIALS")
        return response

    def _sign_up(self, client_token, data) -> Any:
        """
        Handles the logic for signing up a new user. This method processes the provided
        user data, attempts to create a new user, and initializes the root directory
        for the user. If the user already exists, an error message is returned.

        :param client_token: The token identifying the client making the request.
        :type client_token: str
        :param data: A list containing user registration details. It includes the
            username, hashed password, salt, encrypted file master key, and a nonce
            for encryption.
        :type data: list
        :return: A response message indicating the result of the sign-up operation.
            Contains a "SUCCESS" message with a login token if the user is created,
            or an "ERROR" message if the user already exists.
        :rtype: Any
        """
        logging.debug("verb = SIGN_UP")
        username, password_hash, salt, encrypted_file_master_key, nonce = data[0:6]
        if self.users_service.create_user(username, password_hash, salt, encrypted_file_master_key, nonce):
            logging.debug(f"Created User: {username}, with password hash: {password_hash}")
            self.file_service.create_dir(username, None, "/")
            logging.debug(f"Created root directory for user: {username}")
            response = self._write_message("SUCCESS", self.token_service.create_login_token(username))
        else:
            logging.debug(f"User {username} already exists.")
            response = self._write_message("ERROR", client_token, "USER_EXISTS")
        return response

    def _change_username(self, client_token, data, is_token_valid, username):
        """
        Handles the username change operation for a user. Verifies the validity of the client token,
        checks if the new username is available, and processes the username update accordingly.

        :param client_token: Token provided by the client for authentication.
        :type client_token: str
        :param data: A collection containing the new username at index 0.
        :type data: list
        :param is_token_valid: Indicates whether the provided token is valid.
        :type is_token_valid: bool
        :param username: The current username of the user attempting the change.
        :type username: str
        :return: A success message with a new login token if username change is successful, or an
            error message specifying the problem.
        :rtype: str
        """
        logging.debug("verb = CHANGE_USERNAME")
        new_username = data[0]
        if is_token_valid:
            logging.debug(f"Changing username from {username} to {new_username}")
            if self.users_service.change_username(username, new_username):
                return self._write_message("SUCCESS", self.token_service.create_login_token(new_username))
            else:
                return self._write_message("ERROR", client_token, "USERNAME_ALREADY_TAKEN")
        else:
            return self._write_message("ERROR", client_token, "INVALID_TOKEN")

    def _change_password(self, client_token, data, is_token_valid, username):
        """
        Changes the password for the specified user if the token validation is successful.

        This method updates the user's credentials with a new password hash, salt,
        encrypted file master key, and nonce. If the provided token is valid, the method
        logs the operation, updates the user credentials in the `users_service`, and
        returns a success message along with a newly created login token. If the token is
        invalid, it returns an error message indicating an invalid token.

        :param client_token: The token associated with the client that requested
            the password change.
        :type client_token: str
        :param data: A sequence containing the following new credentials: password hash,
            salt, encrypted file master key, and nonce (in that order).
        :type data: Sequence
        :param is_token_valid: Indicates if the provided token is valid for the operation.
        :type is_token_valid: bool
        :param username: The username of the account for which the password is being changed.
        :type username: str
        :return: A success message with a new login token if the token is valid, or an
            error message if the token is invalid.
        :rtype: str
        """
        logging.debug("verb = CHANGE_PASSWORD")
        new_password_hash, new_salt, new_encrypted_file_master_key, new_nonce = data[0:5]
        if is_token_valid:
            logging.debug(f"Changing password for user: {username}")
            self.users_service.update_user_credentials(username, new_password_hash, new_salt, new_encrypted_file_master_key, new_nonce)
            return self._write_message("SUCCESS", self.token_service.create_login_token(username))
        else:
            return self._write_message("ERROR", client_token, "INVALID_TOKEN")

    def _write_message(self, success, token, status_code: str =None):
        """
        Writes a formatted message by combining success status, a token, and an optional status code.
        Logs the initial and final versions of the message during the process.

        :param success: A string indicating the success status.
        :param token: A string representing the token to be included in the message.
        :param status_code: An optional string for the status code. Defaults to None.
        :return: A formatted string message combining the success status, token, and optionally the status code.
        """
        logging.debug(f"Writing Message: Success?: {success}")
        message = success + separator + token
        if status_code:
            message += separator + status_code
        logging.debug(f"Final Message: {message if len(message) < 1000 else f'{message[:1000]}...'}")
        return message


def run_server():
    """
    Initializes and runs the server instance, setting up logging and ensuring proper
    cleanup when the server is terminated.

    This function configures detailed logging output for debug purposes, initializes
    an instance of the server, and registers a cleanup process to close the server
    upon application exit.

    :return: None
    """
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s | %(threadName)-12s | %(levelname)-5s | %(message)s')
    server = ServerClass()
    atexit.register(ServerClass.server_close, server)


if __name__ == "__main__":
    run_server()