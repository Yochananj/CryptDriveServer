import enum

class Verbs(enum.Enum):
    """
    Enumeration for representing various user actions.

    This class defines a set of specific user actions (verbs) that map to corresponding operations
    in the system. Each enum member has an associated string value to facilitate representation
    and use within the application. These actions typically include operations related to user
    account management, file system interaction, and organizational tasks.

    :ivar SIGN_UP: Represents a user signing up with required parameters.
    :type SIGN_UP: str
    :ivar LOG_IN: Represents a user logging in with required credentials.
    :type LOG_IN: str
    :ivar CREATE_FILE: Represents the creation of a new file with required metadata and contents.
    :type CREATE_FILE: str
    :ivar CREATE_DIR: Represents the creation of a new directory with required metadata.
    :type CREATE_DIR: str
    :ivar DOWNLOAD_FILE: Represents downloading a specific file by its path and name.
    :type DOWNLOAD_FILE: str
    :ivar DELETE_FILE: Represents deletion of a specific file by its path and name.
    :type DELETE_FILE: str
    :ivar DELETE_DIR: Represents deletion of a specified directory by its path and name.
    :type DELETE_DIR: str
    :ivar GET_ITEMS_LIST: Represents retrieval of a list of items within a specified path.
    :type GET_ITEMS_LIST: str
    :ivar RENAME_FILE: Represents renaming a specific file with its old and new names.
    :type RENAME_FILE: str
    :ivar RENAME_DIR: Represents renaming a specific directory with its old and new names.
    :type RENAME_DIR: str
    :ivar MOVE_FILE: Represents moving a file from one path to another with its name.
    :type MOVE_FILE: str
    :ivar MOVE_DIR: Represents moving a directory from one path to another with its name.
    :type MOVE_DIR: str
    :ivar CHANGE_USERNAME: Represents changing the username to a new value.
    :type CHANGE_USERNAME: str
    :ivar CHANGE_PASSWORD: Represents changing the password along with corresponding
        security-related details.
    :type CHANGE_PASSWORD: str
    """
    SIGN_UP = "SIGN_UP" # [username, password_hash, salt, encrypted_file_master_key, nonce]
    LOG_IN = "LOG_IN" # [username, password_hash]
    CREATE_FILE = "CREATE_FILE" # [file_path, file_name, nonce] [file_contents]
    CREATE_DIR = "CREATE_DIR" # [path, dir_name]
    DOWNLOAD_FILE = "DOWNLOAD_FILE" # [file_path, file_name]
    DELETE_FILE = "DELETE_FILE" # [file_path, file_name]
    DELETE_DIR = "DELETE_DIR" # [path, dir_name]
    GET_ITEMS_LIST = "GET_ITEMS_LIST" # [path]
    RENAME_FILE = "RENAME_FILE" # [file_path, old_file_name, new_file_name]
    RENAME_DIR = "RENAME_DIR" # [path, old_dir_name, new_dir_name]
    MOVE_FILE = "MOVE_FILE" # [old_file_path, new_file_path, file_name]
    MOVE_DIR = "MOVE_DIR" # [old_dir_path, new_dir_path, dir_name]
    CHANGE_USERNAME = "CHANGE_USERNAME"  # [new_username]
    CHANGE_PASSWORD = "CHANGE_PASSWORD"  # [new_password_hash, new_salt, new_encrypted_file_master_key, new_nonce]