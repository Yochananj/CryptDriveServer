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

        self.server_listen()


    def server_listen(self):
        try:
            self.server.listen(100)
            logging.info(f"Server listening On: {self.host_addr}")
            while self.is_server_running:
                client, client_addr = self.server.accept()
                logging.info(f"\n\n\n\nClient Connected: {client_addr}")
                self.pool.submit(self.begin_client_communication, client, client_addr)
        except KeyboardInterrupt:
            self.server_close()
        finally:
            self.server_close()
            logging.info("Server Closed.")


    def begin_client_communication(self, client, client_addr):
        logging.info(f"Receiving Message From: {client_addr}")
        secure_communication_manager = SecureCommunicationManager(client, self.token_service, self.encryption_token_master_key)
        message = secure_communication_manager.receive_data().decode()
        logging.info(f"Message Received: {message}. Parsing Message...")
        self.parse_message(message, secure_communication_manager)

    def parse_message(self, message, secure_communication_manager: SecureCommunicationManager):
        message_parts = message.split(separator)
        logging.debug(f"Message parts: {message_parts}")
        verb = message_parts[0]
        client_token = message_parts[1]
        data = message_parts[2:len(message_parts)]

        logging.debug(f"Verb: {verb}, Token: {client_token},\n Data: {data[0:len(data)]}")

        is_token_valid = self.token_service.is_token_valid(client_token)

        username = ""
        if is_token_valid:
            username = self.token_service.decode_token(client_token)["username"]
            if self.token_service.token_needs_refreshing(client_token):
                client_token = self.token_service.create_login_token(username=self.token_service.decode_token(client_token)["username"])

        logging.info(f"Is token valid: {is_token_valid}.")

        response = ""
        response_data = ""
        needs_file_contents = False

        match verb:
            case Verbs.SIGN_UP.value:
                logging.debug("verb = SIGN_UP")
                if self.user_service.create_user(data[0], data[1]):
                    logging.debug(f"Created User: {data[0]}, with password hash: {data[1]}")
                    self.file_service.create_dir(data[0], None, "/")
                    logging.debug(f"Created root directory for user: {data[0]}")
                    response = self.write_message("SUCCESS", self.token_service.create_login_token(username=data[0]))
                else:
                    logging.debug(f"User {data[0]} already exists.")
                    response = self.write_message("ERROR", client_token, "USER_EXISTS")

            case Verbs.LOG_IN.value:
                logging.debug("verb = LOG_IN")
                if self.user_service.login(data[0], data[1]):
                    response = self.write_message("SUCCESS", self.token_service.create_login_token(username=data[0]))
                else:
                    response = self.write_message("ERROR", client_token, "INVALID_CREDENTIALS")

            case Verbs.DOWNLOAD_FILE.value:
                logging.debug("verb = DOWNLOAD_FILE")
                if is_token_valid:
                    response_data = self.file_service.get_file_contents(username, data[0], data[1])
                    response = self.write_message("SUCCESS", client_token, "SENDING_DATA")
                else:
                    response = self.write_message("ERROR", client_token, "INVALID_TOKEN")

            case Verbs.GET_ITEMS_LIST.value:
                logging.debug("verb = GET_FILES_LIST")
                if is_token_valid:
                    dirs = self.file_service.get_dirs_list_for_path(username, data[0])
                    logging.debug(f"dirs: {dirs}")
                    files = self.file_service.get_files_list_in_path(username, data[0])
                    logging.debug(f"files: {files}")
                    dirs_dumps = json.dumps([directory.__dict__ for directory in dirs])
                    files_dumps = json.dumps([file_obj.__dict__ for file_obj in files])
                    logging.debug(f"Response data: \n Dirs: {dirs_dumps} \n Files: {files_dumps}")
                    response = self.write_message("SUCCESS", client_token, "SENDING_DATA")
                    response_data = json.dumps(Items(dirs_dumps, files_dumps).__dict__)
                else:
                    response = self.write_message("ERROR", client_token, "INVALID_TOKEN")

            case Verbs.CREATE_FILE.value:
                logging.debug("verb = CREATE_FILE")
                if is_token_valid:
                    if self.file_service.can_create_file(username, data[0], data[1]):
                        response = self.write_message("SUCCESS", client_token, "READY_FOR_DATA")
                        needs_file_contents = True
                    else:
                        response = self.write_message("ERROR", client_token, "FILE_EXISTS")
                else:
                    response = self.write_message("ERROR", client_token, "INVALID_TOKEN")

            case Verbs.DELETE_FILE.value:
                logging.debug("verb = DELETE_FILE")
                if is_token_valid:
                    if self.file_service.delete_file(username, data[0], data[1]):
                        response = self.write_message("SUCCESS", client_token)
                    else:
                        response = self.write_message("ERROR", client_token, "FILE_NOT_FOUND")
                else :
                    response = self.write_message("ERROR", client_token, "INVALID_TOKEN")

            case Verbs.CREATE_DIR.value:
                if is_token_valid:
                    if self.file_service.create_dir(username, data[0], data[1]):
                        response = self.write_message("SUCCESS", client_token)
                    else:
                        response = self.write_message("ERROR", client_token, "DIR_EXISTS")
                else:
                    response = self.write_message("ERROR", client_token, "INVALID_TOKEN")

            case Verbs.DELETE_DIR.value:
                logging.debug("verb = DELETE_DIR")
                if is_token_valid:
                    if self.file_service.delete_dir(username, data[0], data[1]):
                        response = self.write_message("SUCCESS", client_token)
                    else:
                        response = self.write_message("ERROR", client_token, "DIR_NOT_FOUND")
                else:
                    response = self.write_message("ERROR", client_token, "INVALID_TOKEN")

            case Verbs.RENAME_FILE.value:
                if is_token_valid:
                    if self.file_service.rename_file(username, data[0], data[1], data[2]):
                        response = self.write_message("SUCCESS", client_token)
                    else:
                        response = self.write_message("ERROR", client_token, "FILE_NOT_FOUND_OR_ALREADY_EXISTS")
                else:
                    response = self.write_message("ERROR", client_token, "INVALID_TOKEN")

            case Verbs.RENAME_DIR.value:
                if is_token_valid:
                    if self.file_service.rename_dir(username, data[0], data[1], data[2]):
                        response = self.write_message("SUCCESS", client_token)
                    else:
                        response = self.write_message("ERROR", client_token, "DIR_NOT_FOUND_OR_ALREADY_EXISTS")
                else:
                    response = self.write_message("ERROR", client_token, "INVALID_TOKEN")

            case Verbs.MOVE_FILE.value:
                if is_token_valid:
                    if self.file_service.move_file(username, data[0], data[1], data[2]):
                        response = self.write_message("SUCCESS", client_token)
                    else:
                        response = self.write_message("ERROR", client_token, "FILE_NOT_FOUND_OR_ALREADY_EXISTS")
                else:
                    response = self.write_message("ERROR", client_token, "INVALID_TOKEN")

            case Verbs.MOVE_DIR.value:
                if is_token_valid:
                    if self.file_service.move_dir(username, data[0], data[1], data[2]):
                        response = self.write_message("SUCCESS", client_token)
                    else:
                        response = self.write_message("ERROR", client_token, "DIR_NOT_FOUND_OR_ALREADY_EXISTS")
                else:
                    response = self.write_message("ERROR", client_token, "INVALID_TOKEN")

            case _:
                logging.debug("Invalid Verb")
                response = self.write_message("ERROR", client_token, "INVALID_VERB")

        logging.debug(f"Response: {response}")
        logging.debug(f"Response Data: {response_data}")
        logging.debug(f"Response Data Length: {len(response_data)}, type: {type(response_data)}")

        response = response.encode()

        if len(response_data) > 0:
            logging.debug("Adding data to response")
            if isinstance(response_data, str):
                response += string_data_flag + response_data.encode()
            else:
                response += byte_data_flag + response_data
            logging.debug(f"Message with data: {response}")

        secure_communication_manager.respond_to_client(response)

        if needs_file_contents:
            logging.debug("Waiting for Data")
            data_received = secure_communication_manager.receive_data()
            if self.file_service.create_file(username, data[0], data[1], data_received):
                secure_communication_manager.respond_to_client(self.write_message("SUCCESS", client_token, "FILE_CREATED").encode())
            else:
                secure_communication_manager.respond_to_client(self.write_message("ERROR", client_token, "FILE_NOT_CREATED").encode())

    def write_message(self, success, token, status_code=None):
        logging.debug(f"Writing Message: Success?: {success}")
        message = success + separator + token
        if status_code:
            message += separator + status_code
        logging.debug(f"Final Message: {message}")
        return message

    def server_close(self):
        self.server.close()
        self.is_server_running = False



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s | %(threadName)-12s | %(levelname)-5s | %(message)s')
    a = ServerClass()
    atexit.register(ServerClass.server_close, a)


