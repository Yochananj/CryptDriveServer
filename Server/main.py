import json
import logging
import socket
import time
import atexit
from concurrent.futures import ThreadPoolExecutor

from Dependencies.Constants import *
from Dependencies.VerbDictionary import Verbs
from Server.Services.ServerFileService import FileService
from Server.Services.TokensService import TokensService
from Server.Services.UsersService import UsersService


class ServerClass:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_server_running = True

        self.user_service = UsersService()
        self.file_service = FileService(self.user_service)

        self.token_service = TokensService()

        self.host_addr = host_addr
        self.server.bind(self.host_addr)

        self.pool = ThreadPoolExecutor(2*os.cpu_count())

        self.server_listen()


    def server_listen(self):
        self.server.listen(100)
        logging.info(f"Server Listening On: {self.host_addr}")
        try:
            while self.is_server_running:
                client, client_addr = self.server.accept()
                logging.info(f"Client Connected: {client_addr}")
                self.pool.submit(self.begin_client_communication, client, client_addr)
        except KeyboardInterrupt:
            self.server_close()
        finally:
            logging.info("Server Closed.")


    def begin_client_communication(self, client, client_addr):
        logging.info(f"Receiving Message From: {client_addr}")

        data = client.recv(buffer_size).decode()
        logging.debug(f"Received: {data}")
        self.parse_message(client, data)

    def parse_message(self, client, message):
        message_parts = message.split(seperator)

        verb = message_parts[0]
        client_token = message_parts[1]
        data = message_parts[2:len(message_parts)]

        logging.debug(f"Verb: {verb}, Token: {client_token},\n Data: {data[0:len(data)]}")

        is_token_valid = self.token_service.is_token_valid(client_token)

        username = ""
        if is_token_valid :
            username = self.token_service.decode_token(client_token)["username"]
            if self.token_service.does_token_need_refreshing(client_token):
                client_token = self.token_service.create_token(username=self.token_service.decode_token(client_token)["username"])

        logging.info(f"Is token valid: {is_token_valid}.")

        response = ""
        response_data = []
        needs_data = False

        match verb:
            case Verbs.SIGN_UP.value:
                logging.debug("verb = SIGN_UP")
                if self.user_service.create_user(data[0], data[1]):
                    logging.debug(f"Created User: {data[0]}, with password hash: {data[1]}")
                    self.file_service.create_dir(data[0], None, "/")
                    logging.debug(f"Created root directory for user: {data[0]}")
                    response = self.write_message("SUCCESS", self.token_service.create_token(username=data[0]))
                else:
                    logging.debug(f"User {data[0]} already exists.")
                    response = self.write_message("ERROR", client_token, "USER_EXISTS")

            case Verbs.LOG_IN.value:
                logging.debug("verb = LOG_IN")
                if self.user_service.login(data[0], data[1]):
                    response = self.write_message("SUCCESS", self.token_service.create_token(username=data[0]))
                else:
                    response = self.write_message("ERROR", client_token, "INVALID_CREDENTIALS")

            case Verbs.DOWNLOAD_FILE.value:
                logging.debug("verb = DOWNLOAD_FILE")
                if is_token_valid:
                    response_data.append(self.file_service.get_file_contents(username, data[0], data[1]))
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
                    if len(dirs) > 0: response_data.append(json.dumps([directory.__dict__ for directory in dirs]))
                    else: response_data.append(json.dumps([]))
                    if len(files) > 0: response_data.append(json.dumps([file_obj.__dict__ for file_obj in files]))
                    else: response_data.append(json.dumps([]))
                    logging.debug(f"Response data: \n Dirs: {response_data[0]} \n Files: {response_data[1]}")
                    response = self.write_message("SUCCESS", client_token, "SENDING_DATA")
                else:
                    response = self.write_message("ERROR", client_token, "INVALID_TOKEN")

            case Verbs.CREATE_FILE.value:
                logging.debug("verb = CREATE_FILE")
                if is_token_valid:
                    if self.file_service.can_create_file(username, data[0], data[1]):
                        response = self.write_message("SUCCESS", client_token, "READY_FOR_DATA")
                        needs_data = True
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
            case _:
                logging.debug("Invalid Verb")
        logging.debug(f"Sending Response: {response}")
        self.respond_to_client(client, response)

        logging.debug(f"Response Data: {response_data}")
        logging.debug(f"Response Data Length: {len(response_data)}")

        if needs_data:
            logging.debug("Waiting for Data")
            data_received = self.receive_data(client)
            if self.file_service.create_file(username, data[0], data[1], data_received):
                self.respond_to_client(client, self.write_message("SUCCESS", client_token, "FILE_CREATED"))
            else:
                self.respond_to_client(client, self.write_message("ERROR", client_token, "FILE_NOT_CREATED"))

        if len(response_data) > 0:
            logging.debug("Sending Data")
            self.send_data(client, response_data)

    def write_message(self, success, token, status_code=None):
        logging.debug(f"Writing Message: Success?: {success}")
        message = success + seperator + token
        if status_code:
            message += seperator + status_code
        logging.debug(f"Final Message: {message}")
        return message

    def respond_to_client(self, client, message):
        client.send(message.encode())
        logging.debug("Sent Response")


    def send_data(self, client, data: list):
        logging.debug("Starting to send Data")
        str_to_send = b""
        for item in data:
            if isinstance(item, str):
                str_to_send += item.encode()
            else:
                str_to_send += bytes(item)
            str_to_send += seperator.encode()
            logging.debug(f"Current Data: {str_to_send}")
        str_to_send += end_flag
        logging.debug(f"Final Data: {str_to_send}")
        time.sleep(0.5)
        client.sendall(str_to_send)
        logging.debug("Finished Sending Data")

    def server_close(self):
        self.server.close()
        self.is_server_running = False

    def receive_data(self, client):
        finished = False
        received_data = b""

        logging.debug("Initializing data receiving")

        while not finished:
            data_chunk = client.recv(buffer_size)

            if data_chunk.endswith(end_flag):
                finished = True
                received_data += data_chunk[:-len(end_flag)]
            else:
                received_data += data_chunk

        logging.info(f"finished receiving data:")
        if len(received_data) < 5000: logging.info(f"{received_data}")

        return received_data




if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    a = ServerClass()
    atexit.register(ServerClass.server_close, a)


