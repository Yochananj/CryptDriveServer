import logging
import uuid

from Server.DAOs import FilesDatabaseDAO
from Server.DAOs.FilesDiskDAO import FilesDiskDAO
from Server.Services.UsersService import UsersService


class FileService:
    def __init__(self, users_service: UsersService):
        self.files_database_dao = FilesDatabaseDAO.FilesDatabaseDAO()
        self.files_disk_dao = FilesDiskDAO()
        self.users_service = users_service

    def create_file(self, file_owner, user_file_path, user_file_name, file_contents):
        file_owner_id = self.users_service.get_user_id(file_owner)
        logging.debug(f"Creating file for {file_owner}@{user_file_path}/{user_file_name}.")
        if self.can_create_file(file_owner, user_file_path, user_file_name):
            # write to disk
            file_uuid = self._file_uuid_generator()
            self.files_disk_dao.write_file_to_disk(file_owner_id, file_uuid, file_contents)

            # create in database
            file_size = self.files_disk_dao.get_file_size_on_disk(file_owner_id, file_uuid)
            self.files_database_dao.create_file(file_owner_id, user_file_path, file_uuid, user_file_name, file_size)

            # update parent dir item count
            parent_dir_name, parent_dir_path = self._get_parent_dir_name_and_path(user_file_path)
            self.files_database_dao.increase_dir_item_count(file_owner_id, parent_dir_path, parent_dir_name)

            logging.debug(f"File {user_file_name} created.")
            return True
        else:
            logging.error("File already exists.")
            return False

    def delete_file(self, file_owner, user_file_path, user_file_name):
        file_owner_id = self.users_service.get_user_id(file_owner)
        file_uuid = self.files_database_dao.get_file_uuid(file_owner_id, user_file_path, user_file_name)
        if self.files_database_dao.does_file_exist(file_owner_id, user_file_path, user_file_name):
            # delete from disk
            self.files_disk_dao.delete_file_from_disk(file_owner_id, file_uuid)

            # delete from database
            self.files_database_dao.delete_file(file_owner_id, user_file_path, user_file_name)

            # update parent dir item count
            parent_dir_name, parent_dir_path = self._get_parent_dir_name_and_path(user_file_path)
            self.files_database_dao.decrease_dir_item_count(file_owner_id, parent_dir_path, parent_dir_name)

            logging.debug(f"File {user_file_path}/{user_file_name} deleted.")
            return True
        else:
            logging.error("File does not exist.")
            return False

    def create_dir(self, file_owner, user_file_path, user_file_name):
        file_owner_id = self.users_service.get_user_id(file_owner)
        if not self.files_database_dao.does_dir_exist(file_owner_id, user_file_path, user_file_name):
            # create in database
            self.files_database_dao.create_dir(file_owner_id, user_file_path, user_file_name)

            # update parent dir item count
            parent_dir_name, parent_dir_path = self._get_parent_dir_name_and_path(user_file_path)
            self.files_database_dao.increase_dir_item_count(file_owner_id, parent_dir_path, parent_dir_name)

            logging.debug(f"Directory {user_file_path}/{user_file_name} created.")
            return True
        else:
            logging.debug("Directory already exists.")
            return False

    def delete_dir(self, file_owner, user_file_path, user_file_name):
        file_owner_id = self.users_service.get_user_id(file_owner)
        if self.files_database_dao.does_dir_exist(file_owner_id, user_file_path, user_file_name):
            # delete files
            for file in self.files_database_dao.get_all_files_in_path(file_owner_id, user_file_path):
                self.delete_file(file_owner, file.user_file_path, file.user_file_name)
            # delete subdirectories
            for directory in self.files_database_dao.get_all_dirs_in_path(file_owner_id, f"{user_file_path}/{user_file_name}"):
                self.delete_dir(file_owner, directory.user_file_path, directory.user_file_name)
            # delete from database
            self.files_database_dao.delete_dir(file_owner_id, user_file_path, user_file_name)

            # update parent dir item count
            parent_dir_name, parent_dir_path = self._get_parent_dir_name_and_path(user_file_path)
            self.files_database_dao.decrease_dir_item_count(file_owner_id, parent_dir_path, parent_dir_name)

            logging.debug(f"Directory {user_file_path}/{user_file_name} deleted.")
            return True
        else:
            logging.debug("Directory does not exist.")
            return False

    def get_file_contents(self, file_owner, user_file_path, file_name):
        logging.debug(f"Getting file contents for {file_owner}@{user_file_path}/{file_name}.")
        file_owner_id = self.users_service.get_user_id(file_owner)
        file_uuid = self.files_database_dao.get_file_uuid(file_owner_id, user_file_path, file_name)
        file_contents = self.files_disk_dao.get_file_contents(file_owner_id, file_uuid)
        return file_contents

    def get_file_size(self, file_owner, user_file_path, file_name):
        return self.files_database_dao.get_file_size(file_owner, user_file_path, file_name)

    def get_dirs_list_for_path(self, file_owner, path):
        logging.debug(f"Getting dirs list for path {path} for user {file_owner}.")
        file_owner_id = self.users_service.get_user_id(file_owner)
        logging.debug(f"{file_owner} user id: {file_owner_id}")
        dirs_in_path = self.files_database_dao.get_all_dirs_in_path(file_owner_id, path)
        logging.debug(f"Dirs in path: {dirs_in_path}")

        directories_list = []
        for directory in dirs_in_path:
            temp_dir = Directory(f"{directory.user_file_path}/{directory.user_file_name}" if directory.user_file_path != "/" else f"/{directory.user_file_name}", directory.file_size)
            logging.debug(f"Temp dir: {temp_dir.__dict__}")
            directories_list.append(temp_dir)
        logging.debug(f"Dirs list: {[directory.__dict__ for directory in directories_list]}")
        return directories_list

    def get_files_list_in_path(self, file_owner, path):
        logging.debug(f"Getting files list for path {path} for user {file_owner}.")
        file_owner_id = self.users_service.get_user_id(file_owner)
        files = self.files_database_dao.get_all_files_in_path(file_owner_id, path)
        files_list = []
        for file in files:
            files_list.append(File(file.user_file_name, file.file_size))
        logging.debug(f"File tuples list: {[file.__dict__ for file in files_list]}")
        return files_list

    def _file_uuid_generator(self):
        return uuid.uuid4().hex

    def can_create_file(self, file_owner, user_file_path, user_file_name):
        file_owner_id = self.users_service.get_user_id(file_owner)
        if not self.files_database_dao.does_file_exist(file_owner_id, user_file_path, user_file_name):
            return True
        else:
            return False

    def _get_parent_dir_name_and_path(self, user_file_path):
        if user_file_path is None: return None, "/"
        parent_dir_name = user_file_path.split("/")[-1] if user_file_path.split("/")[-1] != "" else "/"
        parent_dir_path = user_file_path[:-len(parent_dir_name)] if user_file_path[:-len(parent_dir_name)] == "/" else user_file_path[:-(len(parent_dir_name) + 1)] if parent_dir_name != "/" else None
        return parent_dir_name, parent_dir_path

class Directory:
    def __init__(self, path, item_count):
        self.path = path
        self.item_count = item_count

class File:
    def __init__(self, name, size):
        self.name = name
        self.size = size

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    user_service = UsersService()
    file_service = FileService(user_service)
    temp_username = str(uuid.uuid4())
    temp_filename = str(uuid.uuid4())
    file_service.users_service.create_user(temp_username, "123456789")
    file_service.create_file(temp_username, "/a/b/c/d/", temp_filename, b"hello world")
    print(file_service.get_file_contents(temp_username,  "/a/b/c/d/", temp_filename))
    file_service.delete_file(temp_username, "/a/b/c/d/", temp_filename)



