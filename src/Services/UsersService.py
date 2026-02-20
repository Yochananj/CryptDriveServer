import logging

from DAOs.UsersDatabaseDAO import UsersDatabaseDAO


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

    def create_user(self, username, password_hash, derived_key_salt, encrypted_file_master_key, encrypted_master_key_nonce):
        """
        Create a new user if the user does not already exist in the system.

        This method checks if a user with the provided username already exists. If the user
        does not exist, it creates a new user with the given credentials and security keys.

        :param username: The unique identifier for the user.
        :type username: str
        :param password_hash: The hashed password of the user.
        :type password_hash: str
        :param derived_key_salt: The cryptographic salt used for deriving user keys.
        :type derived_key_salt: bytes
        :param encrypted_file_master_key: The encrypted file master key associated with the user.
        :type encrypted_file_master_key: bytes
        :param encrypted_master_key_nonce: The nonce used with the encryption of the master key.
        :type encrypted_master_key_nonce: bytes
        :return: A boolean indicating whether the user was successfully created. Returns True
            if the user was created, False otherwise.
        :rtype: bool
        """
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
        """
        Logs in a user by verifying their credentials against the stored records.

        This function checks whether a user exists based on the provided username.
        If the user exists, the password hash is verified against the stored value.
        If the credentials are valid, the appropriate result is returned.

        :param username: The username of the user attempting to log in.
        :type username: str
        :param password_hash: The hashed password corresponding to the provided username.
        :type password_hash: str
        :return: A boolean indicating whether the login attempt was successful.
        :rtype: bool
        """
        logging.info(f"Logging in User, {username}, {password_hash}")
        if self.dao.does_user_exist(username):
            return self.dao.check_username_against_password_hash(username, password_hash)
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

    def update_user_credentials(self, username, new_password_hash, new_salt, new_encrypted_file_master_key, new_nonce):
        """
        Updates the user credentials for the given username. This operation will overwrite
        the existing credentials, including the password hash, salt, encrypted file master
        key, and nonce with the new values provided.

        :param username: The username of the user whose credentials are being updated.
        :param new_password_hash: The updated password hash for the user.
        :param new_salt: The updated cryptographic salt associated with the user.
        :param new_encrypted_file_master_key: The updated encrypted file master key for
            securing the user's files.
        :param new_nonce: The updated nonce used for encryption or cryptographic operations.
        :return: None
        """
        user_id = self.dao.get_user_id(username)
        self.dao.update_user_credentials(user_id, new_password_hash, new_salt, new_encrypted_file_master_key, new_nonce)
