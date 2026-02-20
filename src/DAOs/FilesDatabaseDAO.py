import logging
import peewee
import os
from Dependencies.Constants import server_storage_path

db_path = os.path.join(server_storage_path, "Files.db")
files_db = peewee.SqliteDatabase(db_path)

class FilesDB(peewee.Model):
    """
    Represents a database model for managing file-related information.

    This class is built using the Peewee ORM and is designed to store metadata
    for files such as their ID, owner ID, path, name, size, and other attributes.
    It can be used to organize and query file information efficiently. The
    associated database and indexing are defined in the Meta class.

    :ivar file_id: Auto-generated primary key for the file record.
    :type file_id: int
    :ivar file_owner_id: ID of the user who owns the file.
    :type file_owner_id: int
    :ivar user_file_path: The path of the file provided by the user.
        This value is nullable.
    :type user_file_path: Optional[str]
    :ivar user_file_name: The name of the file provided by the user.
    :type user_file_name: str
    :ivar file_uuid: Unique identifier (UUID) for the file.
        This value is nullable.
    :type file_uuid: Optional[str]
    :ivar file_size: The size of the file in bytes. Defaults to 0.
    :type file_size: int
    :ivar file_nonce: A binary value (nonce) associated with the file.
        This value is nullable.
    :type file_nonce: Optional[bytes]
    :ivar is_directory: Flag indicating whether the entry represents a
        directory. Defaults to False.
    :type is_directory: bool
    """
    file_id = peewee.AutoField()
    file_owner_id = peewee.IntegerField()
    user_file_path = peewee.CharField(null=True)
    user_file_name = peewee.CharField()
    file_uuid = peewee.CharField(null=True)
    file_size = peewee.IntegerField(default=0)
    file_nonce = peewee.BlobField(null=True)
    is_directory = peewee.BooleanField(default=False)

    class Meta:
        """
        Represents the metadata configuration for a specific table, including its database
        connection and indexing strategy.

        The class is used to define the database setup and indexing for managing files and
        directories. It specifies the database to be used and details the unique constraints
        applied to certain fields. This configuration ensures efficient querying and prevents
        duplicate entries based on the defined criteria.

        :ivar database: The database connection object representing the source for storage.
        :type database: type
        :ivar indexes: A tuple defining the database indexes for the table and indicating
                       whether they should enforce uniqueness.
        :type indexes: tuple
        """
        database = files_db
        indexes = (
        (("file_owner_id", "user_file_path", "user_file_name", "is_directory"), True),)

class FilesDatabaseDAO:
    """
    Handles database operations for file and directory management.

    This class provides methods for creating, deleting, renaming, and querying
    files and directories in the database. It abstracts database operations to
    facilitate interaction with a file storage system.
    """
    def __init__(self):
        """
        Initializes and sets up the connection to the database.

        This method establishes a connection to the database and ensures the required
        tables are created. It uses the specified database path to make the connection
        and logs the connection status. The setup is essential for any operations that
        depend on the database.

        :raises DatabaseError: If the connection to the database cannot be established.
        """
        files_db.connect()
        logging.debug(f"Connected to the Database at {db_path}.")
        files_db.create_tables([FilesDB])

    def create_file(self, file_owner_id, user_file_path, file_uuid, user_file_name, file_size, file_nonce):
        """
        Creates a new file record in the database.

        This method is responsible for saving a file's metadata in the database.
        It takes details about the file and ensures they are stored for future
        access or reference. This operation typically involves associating the
        file with its owner and specifying its unique path, name, size, and
        security details.

        :param file_owner_id: The unique identifier of the owner of the file.
        :param user_file_path: The path where the file is stored for the user.
        :param file_uuid: The unique identifier associated with the file.
        :param user_file_name: The original name of the file provided by the user.
        :param file_size: The size of the file in bytes.
        :param file_nonce: A unique value for ensuring file authenticity and security.
        :return: None
        """
        FilesDB.create(
            file_owner_id=file_owner_id,
            user_file_path=user_file_path,
            file_uuid=file_uuid,
            user_file_name=user_file_name,
            file_size=file_size,
            file_nonce=file_nonce
        )
        logging.debug(f"File {user_file_name} created in {file_owner_id}@{user_file_path} in the Database.")

    def delete_file(self, file_owner_id, user_file_path, user_file_name):
        """
        Deletes a file entry from the database based on the provided details. This operation
        removes the file's record from the database by matching the file name, its owner's
        identifier, and the file's path. Useful for cleanup operations where files are no
        longer required or need to be removed explicitly.

        :param file_owner_id: The identifier of the owner of the file.
        :param user_file_path: The path where the file is located relative to the owner directory.
        :param user_file_name: The name of the file to be deleted.
        :return: None
        """
        FilesDB.delete().where(
            FilesDB.user_file_name == user_file_name,
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == user_file_path
        ).execute()
        logging.debug(f"File {user_file_name} deleted from {file_owner_id}/{user_file_path} in the Database.")

    def create_dir(self, file_owner_id, user_file_path, user_file_name):
        """
        Creates a new directory entry in the database for the specified file owner.

        This method interacts with the database to create an entry representing a
        directory. It logs actions performed during the operation.

        :param file_owner_id: The unique identifier of the user who owns the directory
            being created.
        :type file_owner_id: int
        :param user_file_path: The path under which the directory is to be created
            (relative to the user's root directory).
        :type user_file_path: str
        :param user_file_name: The name of the directory to be created.
        :type user_file_name: str
        :return: None
        """
        FilesDB.create(
            file_owner_id=file_owner_id,
            user_file_path=user_file_path,
            user_file_name=user_file_name,
            is_directory=True
        )
        logging.debug(f"Directory {user_file_name} created in {file_owner_id}/{user_file_path} in the Database.")

    def delete_dir(self, file_owner_id, user_dir_path, user_dir_name):
        """
        Deletes a directory from the database for a specified file owner and directory
        path.

        :param file_owner_id: The identifier of the owner of the file or directory.
        :type file_owner_id: int
        :param user_dir_path: The path to the user directory to be deleted.
        :type user_dir_path: str
        :param user_dir_name: The name of the user directory to be deleted.
        :type user_dir_name: str
        :return: None
        """
        FilesDB.delete().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_name == user_dir_name,
            FilesDB.user_file_path == user_dir_path,
            FilesDB.is_directory == True
        ).execute()
        logging.debug(f"Directory {user_dir_name} deleted from {file_owner_id}/{user_dir_path} in the Database.")

    def get_file_uuid(self, file_owner_id, user_file_path, user_file_name):
        """
        Fetches the UUID of a specific file based on the given parameters.

        This method queries the database to locate a file that matches the given
        file owner ID, file path, and file name. The search is restricted to files
        and excludes directories. The UUID of the matching file is then retrieved
        from the database.

        :param file_owner_id: The unique identifier of the file owner.
        :type file_owner_id: int
        :param user_file_path: The path of the file belonging to the owner.
        :type user_file_path: str
        :param user_file_name: The name of the file belonging to the owner.
        :type user_file_name: str
        :return: The UUID of the specified file.
        :rtype: str
        """
        return FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == user_file_path,
            FilesDB.user_file_name == user_file_name,
            FilesDB.is_directory == False
        ).get().file_uuid

    def does_file_exist(self, file_owner_id, user_file_path, user_file_name):
        """
        Checks whether a specific file exists in the database for a given file owner.

        The method verifies the existence of a file by checking against the attributes
        file owner ID, file path, and file name in the database. It only evaluates entries
        that are not directories.

        :param file_owner_id: ID of the owner of the file.
        :type file_owner_id: int
        :param user_file_path: Path to the directory containing the file.
        :type user_file_path: str
        :param user_file_name: Name of the file.
        :type user_file_name: str
        :return: True if the file exists, False otherwise.
        :rtype: bool
        """
        return FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == user_file_path,
            FilesDB.user_file_name == user_file_name,
            FilesDB.is_directory == False
        ).exists()

    def get_all_files_in_path(self, file_owner_id, path):
        """
        Fetches a list of all files in a specified directory path belonging to a specific user.
        The method filters out directories from the result and only includes files.

        :param file_owner_id: The unique identifier of the user who owns the files.
        :type file_owner_id: int
        :param path: The path to the directory in which to search for files.
        :type path: str
        :return: A list of files in the specified path owned by the specified user.
        :rtype: list
        """
        return list(FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == path,
            FilesDB.is_directory == False
        ))

    def get_all_dirs_in_path(self, file_owner_id, path):
        """
        Retrieves all directories in the specified path for the given file owner.

        This function queries the database to fetch a list of directories based on the
        provided file owner's ID and the specified path. It ensures only directories
        that match the input criteria are retrieved.

        :param file_owner_id: The ID of the owner of the file whose directories
            are being queried.
        :type file_owner_id: int
        :param path: The path for which directories need to be retrieved.
        :type path: str
        :return: A list containing directory objects from the database.
        :rtype: list
        """
        return list(FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == path,
            FilesDB.is_directory == True
        ))

    def get_item_count_for_dir(self, file_owner_id, path):
        """
        Calculate the number of items in a specified directory for a given file owner.

        This method retrieves the count of items within a directory specified by the
        owner's ID and the directory path. It interacts with the `FilesDB` database
        to filter by the given `file_owner_id` and `path` parameters.

        :param file_owner_id: The unique identifier representing the owner of the files.
        :type file_owner_id: int
        :param path: The directory path for which item count is calculated.
        :type path: str
        :return: The total number of items present in the specified directory.
        :rtype: int
        """
        return len(list(FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == path,
        )))

    def does_dir_exist(self, file_owner_id, dir_path, dir_name):
        """

        :param file_owner_id:
        :param dir_path:
        :param dir_name:
        :return:
        """
        return FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == dir_path,
            FilesDB.user_file_name == dir_name,
            FilesDB.is_directory == True
        ).exists()

    def rename_and_move_file(self, file_owner_id, old_user_file_path, new_user_file_path, old_user_file_name, new_user_file_name):
        """
        Renames and moves a file for a specified file owner, updates the file's path and
        name in the database accordingly.

        :param file_owner_id: The unique identifier of the file owner.
        :param old_user_file_path: The current file path of the user's file.
        :param new_user_file_path: The new file path where the user's file should be moved.
        :param old_user_file_name: The current name of the user's file.
        :param new_user_file_name: The new name the user's file should be renamed to.
        :return: None
        """
        FilesDB.update(user_file_path=new_user_file_path, user_file_name=new_user_file_name).where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == old_user_file_path,
            FilesDB.user_file_name == old_user_file_name,
            FilesDB.is_directory == False
        ).execute()

    def rename_and_move_dir(self, file_owner_id, old_user_file_path, new_user_file_path, old_user_file_name, new_user_file_name):
        """
        Renames and moves a directory in the database, updating its path and name.

        This method modifies the record of a directory in the database for a specific
        file owner by changing its path and name to the specified new values.

        :param file_owner_id: The identifier of the directory owner.
        :type file_owner_id: int
        :param old_user_file_path: The current file path of the directory.
        :type old_user_file_path: str
        :param new_user_file_path: The new file path to move the directory.
        :type new_user_file_path: str
        :param old_user_file_name: The current name of the directory.
        :type old_user_file_name: str
        :param new_user_file_name: The new name of the directory.
        :type new_user_file_name: str
        :return: The number of rows affected by the update query.
        :rtype: int
        """
        FilesDB.update(user_file_path=new_user_file_path, user_file_name=new_user_file_name).where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == old_user_file_path,
            FilesDB.user_file_name == old_user_file_name,
            FilesDB.is_directory == True
        ).execute()

    def get_file_nonce(self, file_owner_id, user_file_path, user_file_name):
        """
        Fetches the `file_nonce` value from the database for a specific file based on the provided
        file owner ID, file path, and file name. Ensures that the retrieved record corresponds to
        a non-directory file.

        :param file_owner_id: The unique identifier of the file owner.
        :type file_owner_id: int
        :param user_file_path: The directory path where the file is stored.
        :type user_file_path: str
        :param user_file_name: The name of the file.
        :type user_file_name: str
        :return: The nonce value associated with the specified file.
        :rtype: str
        """
        return FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == user_file_path,
            FilesDB.user_file_name == user_file_name,
            FilesDB.is_directory == False
        ).get().file_nonce


    def close_db(self):
        """
        Closes the database connection to ensure resources are properly released.

        This method is responsible for safely closing the database connection
        established during the application's lifecycle. It is critical to call
        this method when the connection is no longer needed to avoid potential
        resource leaks.

        :return: None
        """

        files_db.close()