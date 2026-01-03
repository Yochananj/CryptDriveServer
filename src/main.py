import atexit
import json
import logging
import socket
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from Dependencies.Constants import *
from Dependencies.VerbDictionary import Verbs
from Services.SecureCommunicationManager import SecureCommunicationManager
from Services.ServerFileService import FileService, Items
from Services.TokenService import TokenService
from Services.UsersService import UsersService


class ServerClass:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_server_running = True

        self.user_service = UsersService()
        self.file_service = FileService(self.user_service)

        self.token_service = TokenService()
        self.encryption_token_master_key = AESGCM.generate_key(bit_length=256)
        logging.debug(f"Generated token master key: {self.encryption_token_master_key}")

        self.host_addr = host_addr
        try:
            self.server.bind(self.host_addr)
        except OSError as exception:
            logging.error(f"\n\n\nError starting server: {exception}")
            self.server_close()
            logging.info("Server Closed.")
            return

        self.pool = ThreadPoolExecutor(2*os.cpu_count())

        self._server_listen()

    def server_close(self):
        self.server.close()
        self.is_server_running = False

    def _server_listen(self):
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
        logging.info(f"Receiving Message From: {client_addr}")
        secure_communication_manager = SecureCommunicationManager(client, self.token_service, self.encryption_token_master_key)
        message = secure_communication_manager.receive_data().decode()
        logging.info(f"Message Received: {message}. Parsing Message...")
        self._parse_message(message, secure_communication_manager)

    def _parse_message(self, message, secure_communication_manager: SecureCommunicationManager):
        client_token, data, verb = self._get_data_from_request(message)

        logging.debug(f"Verb: {verb}, Token: {client_token},\n Data: {data[0:len(data)]}")

        client_token, is_token_valid, username = self._handle_token(client_token)

        needs_file_contents, response, response_data = self._handle_action(client_token, data, is_token_valid,
                                                                           username, verb)

        self._handle_response(client_token, data, needs_file_contents, response, response_data,
                              secure_communication_manager, username)

    def _handle_response(self, client_token, data, needs_file_contents, response, response_data,
                         secure_communication_manager: SecureCommunicationManager, username):
        self._log_response_details(response, response_data)

        response = response.encode()

        self._send_initial_response(response, response_data, secure_communication_manager)

        self._receive_data_if_needed(client_token, data, needs_file_contents, secure_communication_manager, username)

    def _get_data_from_request(self, message) -> Any:
        message_parts = message.split(separator)
        logging.debug(f"Message parts: {message_parts}")
        verb = message_parts[0]
        client_token = message_parts[1]
        data = message_parts[2:]
        return client_token, data, verb

    def _handle_token(self, client_token) -> Any:
        is_token_valid = self.token_service.is_token_valid(client_token)

        username = ""
        if is_token_valid:
            username = self.token_service.decode_token(client_token)["username"]
            if self.token_service.token_needs_refreshing(client_token):
                client_token = self.token_service.create_login_token(
                    username=self.token_service.decode_token(client_token)["username"])

        logging.info(f"Is token valid: {is_token_valid}.")
        return client_token, is_token_valid, username

    def _receive_data_if_needed(self, client_token, data, needs_file_contents,
                                secure_communication_manager: SecureCommunicationManager, username):
        if needs_file_contents:
            logging.debug("Waiting for Data")
            data_received = secure_communication_manager.receive_data()
            if self.file_service.create_file(username, data[0], data[1], data_received):
                secure_communication_manager.respond_to_client(
                    self._write_message("SUCCESS", client_token, "FILE_CREATED").encode())
            else:
                secure_communication_manager.respond_to_client(
                    self._write_message("ERROR", client_token, "FILE_NOT_CREATED").encode())

    def _send_initial_response(self, response, response_data, secure_communication_manager: SecureCommunicationManager):
        if len(response_data) > 0:
            logging.debug("Adding data to response")
            if isinstance(response_data, str):
                response += string_data_flag + response_data.encode()
            else:
                response += byte_data_flag + response_data
            logging.debug(f"Message with data: {response}")

        secure_communication_manager.respond_to_client(response)

    def _log_response_details(self, response, response_data):
        logging.debug(f"Response: {response}")
        logging.debug(f"Response Data: {response_data}")
        logging.debug(f"Response Data Length: {len(response_data)}, type: {type(response_data)}")

    def _handle_action(self, client_token, data, is_token_valid, username,
                       verb) -> Any:
        response = ""
        response_data = ""
        needs_file_contents = False

        match verb:
            case Verbs.SIGN_UP.value:
                response = self._sign_up(client_token, data, response)

            case Verbs.LOG_IN.value:
                response = self._login(client_token, data, response)

            case Verbs.DOWNLOAD_FILE.value:
                response, response_data = self._download_file(client_token, data, is_token_valid, response,
                                                              response_data, username)

            case Verbs.GET_ITEMS_LIST.value:
                response, response_data = self._get_items_list(client_token, data, is_token_valid, response,
                                                               response_data, username)

            case Verbs.CREATE_FILE.value:
                needs_file_contents, response = self._create_file(client_token, data, is_token_valid,
                                                                  needs_file_contents, response, username)

            case Verbs.DELETE_FILE.value:
                response = self._delete_file(client_token, data, is_token_valid, response, username)

            case Verbs.CREATE_DIR.value:
                response = self._create_dir(client_token, data, is_token_valid, response, username)

            case Verbs.DELETE_DIR.value:
                response = self._delete_dir(client_token, data, is_token_valid, response, username)

            case Verbs.RENAME_FILE.value:
                response = self._rename_file(client_token, data, is_token_valid, response, username)

            case Verbs.RENAME_DIR.value:
                response = self._rename_dir(client_token, data, is_token_valid, response, username)

            case Verbs.MOVE_FILE.value:
                response = self._move_file(client_token, data, is_token_valid, response, username)

            case Verbs.MOVE_DIR.value:
                response = self._move_dir(client_token, data, is_token_valid, response, username)

            case _:
                logging.debug("Invalid Verb")
                response = self._write_message("ERROR", client_token, "INVALID_VERB")
        return needs_file_contents, response, response_data

    def _move_dir(self, client_token, data, is_token_valid, response, username) -> Any:
        if is_token_valid:
            if self.file_service.move_dir(username, data[0], data[1], data[2]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "DIR_NOT_FOUND_OR_ALREADY_EXISTS")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _move_file(self, client_token, data, is_token_valid, response, username) -> Any:
        if is_token_valid:
            if self.file_service.move_file(username, data[0], data[1], data[2]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "FILE_NOT_FOUND_OR_ALREADY_EXISTS")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _rename_dir(self, client_token, data, is_token_valid, response, username) -> Any:
        if is_token_valid:
            if self.file_service.rename_dir(username, data[0], data[1], data[2]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "DIR_NOT_FOUND_OR_ALREADY_EXISTS")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _rename_file(self, client_token, data, is_token_valid, response, username) -> Any:
        if is_token_valid:
            if self.file_service.rename_file(username, data[0], data[1], data[2]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "FILE_NOT_FOUND_OR_ALREADY_EXISTS")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _delete_dir(self, client_token, data, is_token_valid, response, username) -> Any:
        logging.debug("verb = DELETE_DIR")
        if is_token_valid:
            if self.file_service.delete_dir(username, data[0], data[1]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "DIR_NOT_FOUND")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _create_dir(self, client_token, data, is_token_valid, response, username) -> Any:
        if is_token_valid:
            if self.file_service.create_dir(username, data[0], data[1]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "DIR_EXISTS")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _delete_file(self, client_token, data, is_token_valid, response, username) -> Any:
        logging.debug("verb = DELETE_FILE")
        if is_token_valid:
            if self.file_service.delete_file(username, data[0], data[1]):
                response = self._write_message("SUCCESS", client_token)
            else:
                response = self._write_message("ERROR", client_token, "FILE_NOT_FOUND")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response

    def _create_file(self, client_token, data, is_token_valid, needs_file_contents, response, username) -> Any:
        logging.debug("verb = CREATE_FILE")
        if is_token_valid:
            if self.file_service.can_create_file(username, data[0], data[1]):
                response = self._write_message("SUCCESS", client_token, "READY_FOR_DATA")
                needs_file_contents = True
            else:
                response = self._write_message("ERROR", client_token, "FILE_EXISTS")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return needs_file_contents, response

    def _get_items_list(self, client_token, data, is_token_valid, response, response_data, username) -> Any:
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

    def _download_file(self, client_token, data, is_token_valid, response, response_data, username) -> Any:
        logging.debug("verb = DOWNLOAD_FILE")
        if is_token_valid:
            response_data = self.file_service.get_file_contents(username, data[0], data[1])
            response = self._write_message("SUCCESS", client_token, "SENDING_DATA")
        else:
            response = self._write_message("ERROR", client_token, "INVALID_TOKEN")
        return response, response_data

    def _login(self, client_token, data, response) -> Any:
        logging.debug("verb = LOG_IN")
        if self.user_service.login(data[0], data[1]):
            response = self._write_message("SUCCESS", self.token_service.create_login_token(username=data[0]))
        else:
            response = self._write_message("ERROR", client_token, "INVALID_CREDENTIALS")
        return response

    def _sign_up(self, client_token, data, response) -> Any:
        logging.debug("verb = SIGN_UP")
        if self.user_service.create_user(data[0], data[1]):
            logging.debug(f"Created User: {data[0]}, with password hash: {data[1]}")
            self.file_service.create_dir(data[0], None, "/")
            logging.debug(f"Created root directory for user: {data[0]}")
            response = self._write_message("SUCCESS", self.token_service.create_login_token(username=data[0]))
        else:
            logging.debug(f"User {data[0]} already exists.")
            response = self._write_message("ERROR", client_token, "USER_EXISTS")
        return response

    def _write_message(self, success, token, status_code=None):
        logging.debug(f"Writing Message: Success?: {success}")
        message = success + separator + token
        if status_code:
            message += separator + status_code
        logging.debug(f"Final Message: {message}")
        return message

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s | %(threadName)-12s | %(levelname)-5s | %(message)s')
    a = ServerClass()
    atexit.register(ServerClass.server_close, a)


