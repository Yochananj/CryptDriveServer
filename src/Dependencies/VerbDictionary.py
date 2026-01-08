import enum

class Verbs(enum.Enum):
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