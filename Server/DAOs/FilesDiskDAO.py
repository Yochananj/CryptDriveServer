import logging
import os

from Dependencies.Constants import server_storage_path


class FilesDiskDAO:
    def __init__(self):
        pass

    def write_file_to_disk(self, file_owner_id, file_uuid, file_contents):
        os.makedirs(os.path.join(server_storage_path, str(file_owner_id)), exist_ok=True)
        full_file_path = self.get_full_file_path(file_owner_id, file_uuid)
        with open(full_file_path, "xb") as file:
            file.write(file_contents)
        logging.debug(f"File {full_file_path} written to disk.")

    def get_file_size_on_disk(self, file_owner_id, file_uuid):
        full_file_path = self.get_full_file_path(file_owner_id, file_uuid)
        return os.path.getsize(full_file_path)

    def get_file_contents(self, file_owner_id, file_uuid):
        logging.debug(f"Getting file contents from {file_owner_id}/{file_uuid}.")
        full_file_path = self.get_full_file_path(file_owner_id, file_uuid)
        with open(full_file_path, "rb") as file:
            file_contents = file.read(-1)
        return file_contents

    def delete_file_from_disk(self, file_owner_id, file_uuid):
        os.remove(self.get_full_file_path(file_owner_id, file_uuid))

    def get_full_file_path(self, file_owner_id, file_uuid):
        return os.path.join(server_storage_path, str(file_owner_id), str(file_uuid))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    a = FilesDiskDAO()
    print(a.get_file_size_on_disk(123, "kjhgfcvbhjygfdcvbhytfdxcvbgfdx"))
    print(a.get_file_contents(123, "kjhgfcvbhjygfdcvbhytfdxcvbgfdx"))