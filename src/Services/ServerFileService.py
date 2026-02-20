import logging
import uuid

from DAOs.FilesDatabaseDAO import FilesDatabaseDAO
from DAOs.FilesDiskDAO import FilesDiskDAO
from Services.UsersService import UsersService


class FileService:
    """
    Manages file system operations including creation, deletion, renaming, and moving
    of files and directories. This class integrates with database and disk storage
    to facilitate file management for users.

    This service coordinates with `UsersService` for authentication and user-related
    operations, and uses DAOs to interact with the underlying file system and
    persistent storage.

    :ivar files_database_dao: The data access object for performing database operations
        related to files and directories.
    :type files_database_dao: FilesDatabaseDAO
    :ivar files_disk_dao: The data access object for handling disk-level operations
        for files and directories.
    :type files_disk_dao: FilesDiskDAO
    :ivar users_service: An instance of `UsersService` used to fetch user data and
        manage user-specific operations.
    :type users_service: UsersService
    """
    def __init__(self, users_service: UsersService):
        """
        Initializes the service with the provided users service and sets up DAOs for file
        database and disk operations.

        :param users_service: An instance of UsersService used for user-related
            interactions and operations.
        """
        self.files_database_dao = FilesDatabaseDAO()
        self.files_disk_dao = FilesDiskDAO()
        self.users_service = users_service

    def create_file(self, file_owner, user_file_path, user_file_name, encrypted_file_contents, file_nonce):
        """
        Creates a new file for a specified user with the provided file details.

        This method performs the necessary operations to create a file, including writing the
        encrypted file contents to disk and creating a database record for the file. It ensures
        that the file does not already exist before proceeding.

        :param file_owner: The username of the file owner.
        :type file_owner: str
        :param user_file_path: The path where the file will be stored.
        :type user_file_path: str
        :param user_file_name: The name of the file to be created.
        :type user_file_name: str
        :param encrypted_file_contents: The encrypted contents of the file to be written to disk.
        :type encrypted_file_contents: bytes
        :param file_nonce: A unique nonce value associated with the file for encryption purposes.
        :type file_nonce: bytes
        :return: True if the file was successfully created; False otherwise.
        :rtype: bool
        """
        file_owner_id = self.users_service.get_user_id(file_owner)
        logging.debug(f"Creating file for {file_owner}@{user_file_path if user_file_path != "/" else ""}/{user_file_name}.")
        if self.can_create_file(file_owner, user_file_path, user_file_name):
            # write to disk
            file_uuid = self._generate_file_uuid()
            self.files_disk_dao.write_file_to_disk(file_owner_id, file_uuid, encrypted_file_contents)

            # create in database
            file_size = self.files_disk_dao.get_file_size_on_disk(file_owner_id, file_uuid)
            self.files_database_dao.create_file(file_owner_id, user_file_path, file_uuid, user_file_name, file_size, file_nonce)

            logging.debug(f"File {user_file_name} created.")
            return True
        else:
            logging.error("File already exists.")
            return False

    def delete_file(self, file_owner, user_file_path, user_file_name):
        """Deletes a specific file owned by a user from both disk storage and the database.

        This method locates the file based on the provided owner, path, and name. It first
        validates the existence of the file. If the file exists, it deletes the file from
        disk storage and removes its associated record from the database. If the file does
        not exist, an error is logged, and the operation returns `False`.

        :param file_owner: The username of the file owner whose file is being deleted.
        :type file_owner: str
        :param user_file_path: The path to the directory containing the target file.
        :type user_file_path: str
        :param user_file_name: The name of the file to delete.
        :type user_file_name: str
        :return: A boolean indicating whether the file was successfully deleted.
        :rtype: bool
        """
        file_owner_id = self.users_service.get_user_id(file_owner)
        file_uuid = self.files_database_dao.get_file_uuid(file_owner_id, user_file_path, user_file_name)
        if self.files_database_dao.does_file_exist(file_owner_id, user_file_path, user_file_name):
            # delete from disk
            self.files_disk_dao.delete_file_from_disk(file_owner_id, file_uuid)

            # delete from database
            self.files_database_dao.delete_file(file_owner_id, user_file_path, user_file_name)

            logging.debug(f"File {user_file_path if user_file_path != "/" else ""}/{user_file_name} deleted.")
            return True
        else:
            logging.error("File does not exist.")
            return False

    def create_dir(self, file_owner, user_file_path, user_file_name):
        """
        Creates a directory for the specified user in the database if it does not already exist.

        This method checks whether a directory with the given path and name exists for the specified
        file owner. If the directory does not exist, it creates a new directory in the database.

        :param file_owner: The owner of the directory to be created.
        :type file_owner: str
        :param user_file_path: The path where the directory should be created. Example: "/" for root.
        :type user_file_path: str
        :param user_file_name: The name of the directory to be created.
        :type user_file_name: str
        :return: A boolean indicating whether the directory creation was successful. True if the
            directory was created, False if it already exists.
        :rtype: bool
        """
        file_owner_id = self.users_service.get_user_id(file_owner)
        if not self.files_database_dao.does_dir_exist(file_owner_id, user_file_path, user_file_name):
            # create in database
            self.files_database_dao.create_dir(file_owner_id, user_file_path, user_file_name)

            logging.debug(f"Directory {user_file_path if user_file_path != "/" else ""}/{user_file_name} created.")
            return True
        else:
            logging.debug("Directory already exists.")
            return False

    def delete_dir(self, file_owner, user_file_path, user_file_name):
        """
        Deletes a directory and all its contents, including subdirectories and files, from the user's directory
        structure and the database.

        :param file_owner: The owner of the file or directory to be deleted.
        :type file_owner: str
        :param user_file_path: The path to the parent directory of the directory to be deleted.
        :type user_file_path: str
        :param user_file_name: The name of the directory to be deleted.
        :type user_file_name: str
        :return: True if the directory was successfully deleted, otherwise False.
        :rtype: bool
        """
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

            logging.debug(f"Directory {user_file_path if user_file_path != "/" else ""}/{user_file_name} deleted.")
            return True
        else:
            logging.debug("Directory does not exist.")
            return False

    def rename_file(self, file_owner, user_file_path, old_user_file_name, new_user_file_name):
        """
        Renames a file for a user within their specified file path. Validates the existence
        of the old file and ensures no file with the new name already exists before proceeding
        with the renaming operation.

        :param file_owner: The owner of the file to be renamed.
        :type file_owner: str
        :param user_file_path: The directory path where the file resides.
        :type user_file_path: str
        :param old_user_file_name: The current name of the file to be renamed.
        :type old_user_file_name: str
        :param new_user_file_name: The new name for the file to be renamed.
        :type new_user_file_name: str
        :return: True if the file was successfully renamed, False otherwise.
        :rtype: bool
        """
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
        """
        Moves a file from one user-specified directory to another if the file exists in the old
        directory and a file with the same name does not already exist in the new directory.
        This operation validates the existence and uniqueness of the file in the specified
        directories during the move process.

        :param file_owner: The name or identifier of the user who owns the file.
        :type file_owner: str
        :param old_user_file_path: The directory path from where the file is being moved.
        :type old_user_file_path: str
        :param new_user_file_path: The destination directory path to where the file should be moved.
        :type new_user_file_path: str
        :param file_name: The name of the file being moved.
        :type file_name: str
        :return: Boolean indicating whether the file was successfully moved or not.
        :rtype: bool
        """
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
        """
        Renames a directory belonging to a specified user to a new name, provided that the directory exists, and the new
        name does not already exist within the same path. All files within the directory are also updated to reflect the
        new directory name.

        :param file_owner: User who owns the directory to be renamed
        :type file_owner: str
        :param dir_path: Path to the parent directory containing the directory to be renamed
        :type dir_path: str
        :param old_dir_name: Current name of the directory to be renamed
        :type old_dir_name: str
        :param new_dir_name: New name for the directory
        :type new_dir_name: str
        :return: True if the directory was successfully renamed, False otherwise
        :rtype: bool
        """
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

    def move_dir(self, file_owner, old_parent_dir_path, new_parent_dir_path, dir_name):
        """
        Moves a directory and its contents (subdirectories and files) from an old parent directory path
        to a new parent directory path. Handles renaming and moving of nested subdirectories and files
        within the directory being moved.

        :param file_owner: The owner of the directory to be moved.
        :param old_parent_dir_path: The current path of the parent directory containing the directory
            to be moved.
        :param new_parent_dir_path: The target path where the directory is to be moved.
        :param dir_name: The name of the directory being moved.
        :return: A boolean value indicating whether the directory was successfully moved.
        """
        file_owner_id = self.users_service.get_user_id(file_owner)
        if self.files_database_dao.does_dir_exist(file_owner_id, old_parent_dir_path, dir_name) and not self.files_database_dao.does_dir_exist(file_owner_id, new_parent_dir_path, dir_name):
            logging.debug(f"Moving directory {dir_name} from {old_parent_dir_path} to {new_parent_dir_path}. \nGetting all files in directory...")
            self.files_database_dao.rename_and_move_dir(file_owner_id, old_parent_dir_path, new_parent_dir_path, dir_name, dir_name)

            dirs = self.files_database_dao.get_all_dirs_in_path(file_owner_id, f"{old_parent_dir_path if old_parent_dir_path != "/" else ""}/{dir_name}")
            for directory in dirs:
                self.move_dir(file_owner, f"{old_parent_dir_path if old_parent_dir_path != "/" else ""}/{dir_name}", f"{new_parent_dir_path if new_parent_dir_path != "/" else ""}/{dir_name}", directory.user_file_name)

            files = self.files_database_dao.get_all_files_in_path(file_owner_id,f"{old_parent_dir_path if old_parent_dir_path != "/" else ""}/{dir_name}")
            for file in files:
                self.files_database_dao.rename_and_move_file(
                    file_owner_id=file_owner_id,
                    old_user_file_path=file.user_file_path,
                    new_user_file_path=f"{new_parent_dir_path if new_parent_dir_path != "/" else ""}/{dir_name}",
                    old_user_file_name=file.user_file_name,
                    new_user_file_name=file.user_file_name
                )
            return True
        else:
            logging.error("Directory cannot be moved. Either it does not exist or a directory with the new name already exists.")
            return False

    def get_file_contents_and_nonce(self, file_owner, user_file_path, file_name):
        """
        Retrieves the contents and nonce of a file specified by its owner, file path,
        and name. This function communicates with underlying services and databases
        to fetch the necessary data by user and file identifiers.

        :param file_owner: The user who owns the file.
        :type file_owner: str
        :param user_file_path: The directory path where the file resides under the user's
            storage.
        :type user_file_path: str
        :param file_name: The name of the file whose contents and nonce should be
            retrieved.
        :type file_name: str
        :return: A tuple containing the file contents and its associated nonce.
        :rtype: tuple
        """
        logging.debug(f"Getting file contents for {file_owner}@{user_file_path}/{file_name}.")
        file_owner_id = self.users_service.get_user_id(file_owner)
        logging.debug(f"{file_owner} user id: {file_owner_id} \n Getting file uuid...")
        file_uuid = self.files_database_dao.get_file_uuid(file_owner_id, user_file_path, file_name)
        logging.debug(f"File uuid: {file_uuid}\n Getting file contents from disk...")
        file_contents = self.files_disk_dao.get_file_contents(file_owner_id, file_uuid)

        file_nonce = self.files_database_dao.get_file_nonce(file_owner_id, user_file_path, file_name)
        return file_contents, file_nonce


    def get_dirs_list_for_path(self, file_owner, path):
        """
        Generates a list of directories within a specified path for a given file owner.

        This method interacts with a user service to retrieve the user's unique
        identifier and a database DAO to fetch directory information, constructing
        directory objects that include both the path and item counts for the directories.

        :param file_owner: The username of the file owner.
        :type file_owner: str
        :param path: The path from which the directory list is to be retrieved.
        :type path: str
        :return: A list of Directory objects representing the directories found in the
                 specified path, each with its path and item count information.
        :rtype: list[Directory]
        """
        logging.debug(f"Getting dirs list for path {path} for user {file_owner}.")
        file_owner_id = self.users_service.get_user_id(file_owner)
        logging.debug(f"{file_owner} user id: {file_owner_id}")
        dirs_in_path = self.files_database_dao.get_all_dirs_in_path(file_owner_id, path)
        logging.debug(f"Dirs in path: {dirs_in_path}")

        directories_list = []
        for d in dirs_in_path:
            temp_path = f"{d.user_file_path if d.user_file_path != "/" else ""}/{d.user_file_name}"
            temp_dir = Directory(temp_path, self.files_database_dao.get_item_count_for_dir(file_owner_id ,temp_path))
            logging.debug(f"Temp dir: {temp_dir.__dict__}")
            directories_list.append(temp_dir)
        logging.debug(f"Dirs list: {[directory.__dict__ for directory in directories_list]}")
        return directories_list

    def get_files_list_in_path(self, file_owner, path):
        """
        Retrieves a list of files located in the specified path for a given user.

        This function fetches all files stored in the specified directory path associated with the
        provided user and returns a list of file objects. It uses a user service to determine the
        user's ID and interacts with a data access object (DAO) to obtain the files.

        :param file_owner: The username or identifier of the file owner.
        :type file_owner: str
        :param path: The directory path from which to retrieve the files.
        :type path: str
        :return: A list of File objects, each representing a file with its name and size.
        :rtype: list[File]
        """
        logging.debug(f"Getting files list for path {path} for user {file_owner}.")
        file_owner_id = self.users_service.get_user_id(file_owner)
        files = self.files_database_dao.get_all_files_in_path(file_owner_id, path)
        files_list = []
        for file in files:
            files_list.append(File(file.user_file_name, file.file_size))
        logging.debug(f"File tuples list: {[file.__dict__ for file in files_list]}")
        return files_list

    def _generate_file_uuid(self):
        """
        Generates a unique file UUID.

        This method generates a new unique identifier for a file using the
        UUID version 4 standard and returns its hexadecimal representation.

        :return: A string representing the generated UUID in hexadecimal format
        :rtype: str
        """
        return uuid.uuid4().hex

    def can_create_file(self, file_owner, user_file_path, user_file_name):
        """
        Determines if a file can be created by verifying its nonexistence in the file database.

        This function checks whether a file with the given owner, path, and name already exists
        in the file database. If the file does not exist, the function returns True, indicating
        that the file can be created. Otherwise, it returns False.

        :param file_owner: The owner of the file, represented as a username.
        :type file_owner: str
        :param user_file_path: The directory path where the file is intended to be created.
        :type user_file_path: str
        :param user_file_name: The name of the file to be created.
        :type user_file_name: str
        :return: A boolean value indicating whether the file can be created. Returns True if
            the file does not exist, otherwise returns False.
        :rtype: bool
        """
        file_owner_id = self.users_service.get_user_id(file_owner)
        if not self.files_database_dao.does_file_exist(file_owner_id, user_file_path, user_file_name):
            return True
        else:
            return False

    def _get_parent_dir_name_and_path(self, user_file_path):
        """
        Extracts and returns the parent directory name and path of a given file path.

        This method is used to analyze the provided file path and determine the
        parent directory's name and its corresponding path.

        :param user_file_path: str
            The file path for which the parent directory information is required.
            It can be `None`.

        :return: tuple[str | None, str | None]
            A tuple containing the name of the parent directory and the path to
            the parent directory. If the `user_file_path` is `None`, returns
            a tuple of (`None`, "/").
        """
        if user_file_path is None: return None, "/"
        parent_dir_name = user_file_path.split("/")[-1] if user_file_path.split("/")[-1] != "" else "/"
        parent_dir_path = user_file_path[:-len(parent_dir_name)] if user_file_path[:-len(parent_dir_name)] == "/" else user_file_path[:-(len(parent_dir_name) + 1)] if parent_dir_name != "/" else None
        return parent_dir_name, parent_dir_path

    def close_db(self):
        """
        Closes the database connection established by the `files_database_dao` instance. This operation ensures
        the database resources are properly released and avoids potential connection leaks.

        :raises Exception: If any issue occurs during the closure of the database connection.
        """
        self.files_database_dao.close_db()


class Directory:
    """
    Represents a filesystem directory.

    This class provides a way to encapsulate a directory's path and the number of
    items it contains. It is intended for use in managing file system resources and
    performing operations that involve directory-related metadata.

    :ivar path: The file system path of the directory.
    :type path: str
    :ivar item_count: The number of items contained in the directory.
    :type item_count: int
    """
    def __init__(self, path, item_count):
        """
        Initializes a new instance of the class with specified path and item count.
        This constructor assigns the provided path to the path attribute and initializes
        the item count of the instance.

        :param path: A string representing the file system path.
        :param item_count: An integer specifying the number of items.
        """
        self.path = path
        self.item_count = item_count

class File:
    """
    Represents a file with a name and size.

    This class is designed to manage basic file metadata such as its
    name and size. Instances of this class can store and retrieve
    information about files.

    :ivar name: The name of the file.
    :type name: str
    :ivar size: The size of the file in bytes.
    :type size: int
    """
    def __init__(self, name, size):
        """
        Initializes an instance of the class, defining its name and size attributes.

        :param name: The name associated with the instance.
        :param size: The size value associated with the instance.

        """
        self.name = name
        self.size = size

class Items:
    """
    Represents a collection of directories and files.

    This class is designed to store and manage a set of directories and files
    provided during its initialization. It serves as a container to organize
    and handle these resources effectively.

    :ivar dirs_dumps: Contains a list or collection of directory-related data.
    :type dirs_dumps: any
    :ivar files_dumps: Contains a list or collection of file-related data.
    :type files_dumps: any
    """
    def __init__(self, dirs_dumps, files_dumps):
        """
        Initializes the object with directory and file dump data.

        :param dirs_dumps: Represents the directories data dump. Specific expected structure
            or format of the data dump should be consistent across usage.
        :type dirs_dumps: Any
        :param files_dumps: Represents the files data dump. Specific expected structure
            or format of the data dump should be consistent across usage.
        :type files_dumps: Any
        """
        self.dirs_dumps = dirs_dumps
        self.files_dumps = files_dumps


