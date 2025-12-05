import logging
import uuid

from DAOs.FilesDatabaseDAO import FilesDatabaseDAO
from DAOs.FilesDiskDAO import FilesDiskDAO
from Services.UsersService import UsersService


class FileService:
    def __init__(self, users_service: UsersService):
        self.files_database_dao = FilesDatabaseDAO()
        self.files_disk_dao = FilesDiskDAO()
        self.users_service = users_service

    def create_file(self, file_owner, user_file_path, user_file_name, file_contents):
        file_owner_id = self.users_service.get_user_id(file_owner)
        logging.debug(f"Creating file for {file_owner}@{user_file_path if user_file_path != "/" else ""}/{user_file_name}.")
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

            logging.debug(f"File {user_file_path if user_file_path != "/" else ""}/{user_file_name} deleted.")
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

            logging.debug(f"Directory {user_file_path if user_file_path != "/" else ""}/{user_file_name} created.")
            return True
        else:
            logging.debug("Directory already exists.")
            return False

    def delete_dir(self, file_owner, user_file_path, user_file_name):
        file_owner_id = self.users_service.get_user_id(file_owner)
        if self.files_database_dao.does_dir_exist(file_owner_id, user_file_path, user_file_name):
            # delete files
            for file in self.files_database_dao.get_all_files_in_path(file_owner_id, user_file_path + user_file_name):
                self.delete_file(file_owner, file.user_file_path, file.user_file_name)
            # delete subdirectories
            for directory in self.files_database_dao.get_all_dirs_in_path(file_owner_id, f"{user_file_path if user_file_path != "/" else ""}/{user_file_name}"):
                self.delete_dir(file_owner, directory.user_file_path, directory.user_file_name)
            # delete from database
            self.files_database_dao.delete_dir(file_owner_id, user_file_path, user_file_name)

            # update parent dir item count
            parent_dir_name, parent_dir_path = self._get_parent_dir_name_and_path(user_file_path)
            self.files_database_dao.decrease_dir_item_count(file_owner_id, parent_dir_path, parent_dir_name)

            logging.debug(f"Directory {user_file_path if user_file_path != "/" else ""}/{user_file_name} deleted.")
            return True
        else:
            logging.debug("Directory does not exist.")
            return False

    def rename_file(self, file_owner, user_file_path, old_user_file_name, new_user_file_name):
        file_owner_id = self.users_service.get_user_id(file_owner)
        if self.files_database_dao.does_file_exist(file_owner_id, user_file_path, old_user_file_name) and not self.files_database_dao.does_file_exist(file_owner_id, user_file_path, new_user_file_name):
            logging.debug(f"Renaming file {old_user_file_name} to {new_user_file_name}.")
            self.files_database_dao.rename_and_move_file(
                file_owner_id=file_owner_id,
                old_user_file_path=user_file_path,
                new_user_file_path=user_file_path,
                old_user_file_name=old_user_file_name,
                new_user_file_name=new_user_file_name
            )
            return True
        else:
            logging.error("File cannot be renamed. Either it does not exist or a file with the new name already exists.")
            return False

    def move_file(self, file_owner, old_user_file_path, new_user_file_path, file_name):
        file_owner_id = self.users_service.get_user_id(file_owner)
        if self.files_database_dao.does_file_exist(file_owner_id, old_user_file_path, file_name) and not self.files_database_dao.does_file_exist(file_owner_id, new_user_file_path, file_name):
            logging.debug(f"Moving file from {old_user_file_path} to {new_user_file_path}.")
            self.files_database_dao.rename_and_move_file(
                file_owner_id=file_owner_id,
                old_user_file_path=old_user_file_path,
                new_user_file_path=new_user_file_path,
                old_user_file_name=file_name,
                new_user_file_name=file_name
            )
            return True
        else:
            logging.error("File cannot be moved. Either it does not exist or a file with the new name already exists.")
            return False

    def rename_dir(self, file_owner, dir_path, old_dir_name, new_dir_name):
        file_owner_id = self.users_service.get_user_id(file_owner)
        if self.files_database_dao.does_dir_exist(file_owner_id, dir_path, old_dir_name) and not self.files_database_dao.does_dir_exist(file_owner_id, dir_path, new_dir_name):
            logging.debug(f"Renaming directory {old_dir_name} to {new_dir_name}. \nGetting all files in directory...")
            for file in self.files_database_dao.get_all_files_in_path(file_owner_id, f"{dir_path if dir_path != "/" else ""}/{old_dir_name}"):
                self.files_database_dao.rename_and_move_file(
                    file_owner_id=file_owner_id,
                    old_user_file_path=file.user_file_path,
                    new_user_file_path=f"{dir_path if dir_path != "/" else ""}/{new_dir_name}",
                    old_user_file_name=file.user_file_name,
                    new_user_file_name=file.user_file_name
                )

            self.files_database_dao.rename_and_move_dir(file_owner_id, dir_path, dir_path, old_dir_name, new_dir_name)
            return True
        else:
            logging.error("Directory cannot be renamed. Either it does not exist or a directory with the new name already exists.")
            return False

    def move_dir(self, file_owner, old_dir_path, new_dir_path, dir_name):
        file_owner_id = self.users_service.get_user_id(file_owner)
        if self.files_database_dao.does_dir_exist(file_owner_id, old_dir_path, dir_name) and not self.files_database_dao.does_dir_exist(file_owner_id, new_dir_path, dir_name):
            logging.debug(f"Moving directory {dir_name} form {old_dir_path} to {new_dir_path}. \nGetting all files in directory...")
            files = list(self.files_database_dao.get_all_files_in_path(file_owner_id,f"{old_dir_path if old_dir_path != "/" else ""}/{dir_name}"))
            for file in files:
                self.files_database_dao.rename_and_move_file(
                    file_owner_id=file_owner_id,
                    old_user_file_path=file.user_file_path,
                    new_user_file_path=f"{new_dir_path if new_dir_path != "/" else ""}/{dir_name}",
                    old_user_file_name=file.user_file_name,
                    new_user_file_name=file.user_file_name
                )

            self.files_database_dao.rename_and_move_dir(file_owner_id, old_dir_path, dir_name, dir_name)
            return True
        else:
            logging.error(
                "Directory cannot be moved. Either it does not exist or a directory with the new name already exists.")
            return False

    def get_file_contents(self, file_owner, user_file_path, file_name):
        logging.debug(f"Getting file contents for {file_owner}@{user_file_path}/{file_name}.")
        file_owner_id = self.users_service.get_user_id(file_owner)
        logging.debug(f"{file_owner} user id: {file_owner_id} \n Getting file uuid...")
        file_uuid = self.files_database_dao.get_file_uuid(file_owner_id, user_file_path, file_name)
        logging.debug(f"File uuid: {file_uuid}\n Getting file contents from disk...")
        file_contents = self.files_disk_dao.get_file_contents(file_owner_id, file_uuid)
        return file_contents


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

class Items:
    def __init__(self, dirs_dumps, files_dumps):
        self.dirs_dumps = dirs_dumps
        self.files_dumps = files_dumps

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



