import logging

from src.DAOs.UsersDatabaseDAO import UsersDatabaseDAO


class UsersService:
    def __init__(self):
        self.dao = UsersDatabaseDAO()

    def create_user(self, username, password_hash, derived_key_salt, encrypted_file_master_key, encrypted_master_key_nonce):
        logging.debug("Checking if user exists already")
        if not self.dao.does_user_exist(username):
            logging.debug("User does not exist. Creating...")
            self.dao.create_user(username, password_hash, derived_key_salt, encrypted_file_master_key, encrypted_master_key_nonce)
            logging.debug(f"User {username} created.")
            return True
        else:
            logging.debug(f"User {username} already exists.")
            return False

    def login(self, username, password_hash):
        logging.info(f"Logging in User, {username}, {password_hash}")
        if self.dao.does_user_exist(username):
            return self.dao.check_username_against_password_hash(username, password_hash)
        else:
            return False

    def change_username(self, username, new_username) -> bool:
        user_id = self.dao.get_user_id(username)
        if not self.dao.does_user_exist(new_username):
            self.dao.change_username(user_id, new_username)
            return True
        else:
            return False

    def get_user_derived_key_salt_and_encrypted_master_key_and_nonce(self, username) -> tuple[bytes, bytes, bytes]:
        return self.dao.get_derived_key_salt(username), self.dao.get_encrypted_master_key(username), self.dao.get_encrypted_master_key_nonce(username)

    def delete_user(self, username):
        self.dao.delete_user(username)
        logging.debug(f"User {username} deleted.")

    def get_user_id(self, username):
        return self.dao.get_user_id(username)

    def update_user_credentials(self, username, new_password_hash, new_salt, new_encrypted_file_master_key, new_nonce):
        user_id = self.dao.get_user_id(username)
        self.dao.update_user_credentials(user_id, new_password_hash, new_salt, new_encrypted_file_master_key, new_nonce)
