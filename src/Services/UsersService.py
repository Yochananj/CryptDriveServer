import logging

from DAOs.UsersDatabaseDAO import UsersDatabaseDAO
from Services.PasswordHashingManager import hash_password, verify_password


class UsersService:
    """
    This class provides services for managing user data, including creating users,
    authenticating users, updating usernames, retrieving security keys, deleting users,
    and updating user credentials. It interacts with a UsersDatabaseDAO object to
    perform database-related operations.

    :ivar dao: The data access object responsible for interacting with the users' database.
    :type dao: UsersDatabaseDAO
    """
    def __init__(self):
        """
        Represents the initializer method for setting up the required dependencies of the class.

        This method is responsible for initializing the necessary components or dependencies
        that will be used throughout the object's lifecycle.
        """
        self.dao = UsersDatabaseDAO()

    def create_user(self, username, password, derived_key_salt, encrypted_file_master_key, encrypted_master_key_nonce):
        """
        Creates a new user in the system if the user does not already exist.

        This method checks whether a username already exists in the system. If the user
        does not exist, it hashes the given password and stores it along with the other
        relevant details, such as cryptographic salts and keys, in the database. If the
        user exists, no creation action is performed.

        :param username: The username of the new user to be created
        :type username: str
        :param password: The plaintext password for the new user to be hashed and stored
        :type password: str
        :param derived_key_salt: The salt used for deriving the user's encryption keys
        :type derived_key_salt: bytes
        :param encrypted_file_master_key: The user's file master key, encrypted for secure storage
        :type encrypted_file_master_key: bytes
        :param encrypted_master_key_nonce: The nonce used for encrypting and decrypting the
            file master key
        :type encrypted_master_key_nonce: bytes
        :return: True if the user was successfully created, False if the user already exists
        :rtype: bool
        """
        logging.debug("Checking if user exists already")
        if not self.dao.does_user_exist(username):
            logging.debug("User does not exist. Creating...")
            password_hash = hash_password(password)
            self.dao.create_user(username, password_hash, derived_key_salt, encrypted_file_master_key, encrypted_master_key_nonce)
            logging.debug(f"User {username} created.")
            return True
        else:
            logging.debug(f"User {username} already exists.")
            return False

    def login(self, username, password):
        """
        Log in a user by verifying their credentials.

        This function checks if the user exists and validates the provided password
        against the stored password hash. If the user exists and the password matches,
        authentication is successful.

        :param username: The username of the user trying to log in.
        :type username: str
        :param password: The plain text password provided by the user.
        :type password: str
        :return: True if the user exists and the password is correct, otherwise False.
        :rtype: bool
        """
        logging.info(f"Logging in User, {username}, {password}")
        if self.dao.does_user_exist(username):
            stored_hash = self.dao.get_password_hash_for_username(username)
            return verify_password(password, stored_hash)
        else:
            return False

    def change_username(self, username, new_username) -> bool:
        """
        Changes the username of an existing user to a new username.

        This method retrieves the user ID of the existing username and ensures
        that the new username is not already in use. If the new username is available,
        the username is updated to the new value.

        :param username: The current username of the user.
        :type username: str
        :param new_username: The new desired username to update to.
        :type new_username: str
        :return: A boolean value indicating whether the username was successfully
            updated. Returns True if the update was successful, otherwise False.
        :rtype: bool
        """
        user_id = self.dao.get_user_id(username)
        if not self.dao.does_user_exist(new_username):
            self.dao.change_username(user_id, new_username)
            return True
        else:
            return False

    def get_user_derived_key_salt_and_encrypted_master_key_and_nonce(self, username) -> tuple[bytes, bytes, bytes]:
        """
        Retrieves the derived key salt, encrypted master key, and corresponding nonce
        for the given username. This function communicates with the data access
        layer (DAO) to fetch the necessary encryption-related details for a user.

        :param username: The username of the user whose encryption-related keys
            and data are to be retrieved.
        :type username: str
        :return: A tuple containing the derived key salt, encrypted master key,
            and the nonce associated with the encrypted master key.
        :rtype: tuple[bytes, bytes, bytes]
        """
        return self.dao.get_derived_key_salt(username), self.dao.get_encrypted_master_key(username), self.dao.get_encrypted_master_key_nonce(username)

    def delete_user(self, username):
        """
        Deletes a user from the system by username.

        This method removes a user from the database or storage using the given
        username, and logs the deletion action for debugging and auditing purposes.

        :param username: The username of the user to be deleted.
        :type username: str
        :return: None
        """
        self.dao.delete_user(username)
        logging.debug(f"User {username} deleted.")

    def get_user_id(self, username):
        """
        Retrieve the user ID associated with a given username.

        This method interacts with the data access object (DAO) to obtain the unique
        user ID linked to the provided username. The username must be a valid
        identifier for a registered user.

        :param username: The username of the user whose ID is being retrieved.
        :type username: str
        :return: The unique identifier of the user.
        :rtype: int
        """
        return self.dao.get_user_id(username)

    def update_user_credentials(self, username, old_password, new_password, new_salt, new_encrypted_file_master_key, new_nonce):
        """
        Updates the credentials of a user in the system by hashing the new password and
        storing the updated information in the database.

        :param username: The unique identifier of the user whose credentials need to
            be updated.
        :type username: str
        :param old_password: The old password used by the user, which will be
            verified before being updated to the new password provided.
        :param new_password: The new password provided by the user, which will be
            hashed and stored securely.
        :type new_password: str
        :param new_salt: The new cryptographic salt used for hashing the password.
        :type new_salt: str
        :param new_encrypted_file_master_key: The updated encrypted file master key
            associated with the user.
        :type new_encrypted_file_master_key: bytes
        :param new_nonce: The new nonce value required for cryptographic operations.
        :type new_nonce: bytes
        :return: None
        :rtype: None
        """
        if not verify_password(old_password, self.dao.get_password_hash_for_username(username)):
            return False
        else:
            user_id = self.dao.get_user_id(username)
            new_password_hash = hash_password(new_password)
            self.dao.update_user_credentials(user_id, new_password_hash, new_salt, new_encrypted_file_master_key, new_nonce)
            return True


    def verify_password_for_username(self, username, password):
        """
        Verifies if the provided password matches the stored password hash for a given username.

        :param username: The username for which the password needs to be verified.
        :type username: str
        :param password: The password to verify against the stored password hash.
        :type password: str

        :return: True if the provided password matches the stored password hash for the given username,
            otherwise False.
        :rtype: bool
        """
        return verify_password(password, self.dao.get_password_hash_for_username(username))
