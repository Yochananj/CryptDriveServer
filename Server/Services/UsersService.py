import logging

from Server.DAOs.UsersDatabaseDAO import UsersDatabaseDAO


class UsersService:
    def __init__(self):
        self.dao = UsersDatabaseDAO()

    def create_user(self, username, password_hash):
        logging.debug("Checking if user exists already")
        if not self.dao.does_user_exist(username):
            logging.debug("User does not exist. Creating...")
            self.dao.create_user(username, password_hash)
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

    def delete_user(self, username):
        self.dao.delete_user(username)
        logging.debug(f"User {username} deleted.")

    def get_user_id(self, username):
        return self.dao.get_user_id(username)
