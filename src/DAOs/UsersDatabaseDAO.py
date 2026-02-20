import logging
import os
import peewee
from Dependencies.Constants import server_storage_path

db_path = os.path.join(server_storage_path, "Users.db")
users_db = peewee.SqliteDatabase(db_path)
os.makedirs(os.path.dirname(db_path), exist_ok=True)

class UsersDB(peewee.Model):
    """
    Representation of the UsersDB model.

    UsersDB is a database model that represents user information and
    security-related data for users in the system. It includes fields for
    basic identification, cryptographic data, and handles automatic indexing
    of usernames to ensure uniqueness.

    :ivar user_id: Auto-incrementing primary key for the user.
    :type user_id: int
    :ivar username: Unique username of the user.
    :type username: str
    :ivar password_hash: Hashed representation of the user's password.
    :type password_hash: str
    :ivar derived_key_salt: Cryptographic salt used during the derivation of
                            encryption keys.
    :type derived_key_salt: bytes
    :ivar encrypted_master_key: Encrypted master key used for accessing
                                sensitive data.
    :type encrypted_master_key: bytes
    :ivar encrypted_master_key_nonce: Nonce associated with the encrypted
                                      master key for security purposes.
    :type encrypted_master_key_nonce: bytes
    """
    user_id = peewee.AutoField()
    username = peewee.CharField()
    password_hash = peewee.CharField()
    derived_key_salt = peewee.BlobField()
    encrypted_master_key = peewee.BlobField()
    encrypted_master_key_nonce = peewee.BlobField()

    class Meta:
        """
        Represents metadata configuration for a database model.

        This class is typically used to configure database-related settings
        for the associated model, such as defining the database to use and
        any indexes.

        This meta configuration is utilized by the associated ORM to enforce
        database relationships, constraints, and indexing rules.

        :ivar database: The database associated with the model.
        :type database: Any
        :ivar indexes: A sequence of indexing configurations for the model. Each
            index is defined as a tuple, where the first element is a tuple of fields
            to be indexed, and the second element specifies whether the index is
            unique.
        :type indexes: tuple
        """
        database = users_db
        indexes = ((('username',),True),)

class UsersDatabaseDAO:
    """
    Manages user records and credentials in the UsersDB database.

    Detailed management of user data including creation, deletion, retrieval, and updates
    of user credentials and associated cryptographic details. Provides utilities to securely
    manage user information, ensuring proper handling of encryption-related attributes.
    """
    def __init__(self):
        """
        Connects to the user database and initializes the required table for managing user records.

        This constructor method connects to the database and creates the necessary tables if they
        do not already exist, ensuring that the environment is prepared for user data storage and
        retrieval operations.

        """
        users_db.connect()
        logging.debug(f"Connected to the Database at {db_path}.")
        UsersDB.create_table([UsersDB])

    def create_user(self, username, password_hash, derived_key_salt, encrypted_file_master_key, encrypted_master_key_nonce):
        """
        Creates a new user in the database with the specified credentials and encryption details.

        This method is used to store credentials, encryption salt, and master keys
        for secure access management in the UsersDB.

        :param username: The username of the user to be created.
        :type username: str
        :param password_hash: A hashed representation of the user's password.
        :type password_hash: str
        :param derived_key_salt: The salt used during key derivation for the password.
        :type derived_key_salt: str
        :param encrypted_file_master_key: The encrypted file master key of the user.
        :type encrypted_file_master_key: str
        :param encrypted_master_key_nonce: The nonce used for encrypting the user master key.
        :type encrypted_master_key_nonce: str
        :return: None
        """
        UsersDB.create(
            username=username,
            password_hash=password_hash,
            derived_key_salt=derived_key_salt,
            encrypted_master_key=encrypted_file_master_key,
            encrypted_master_key_nonce=encrypted_master_key_nonce
        )
        logging.debug(f"User {username} created in the Database (ID: {self.get_user_id(username)})")

    def delete_user(self, username):
        """
        Deletes a user record from the database based on the provided username.

        This method removes the user entry corresponding to the given username
        from the database by executing an SQL delete operation. Logging is used
        to confirm the deletion action.

        :param username: The username of the user to be deleted.
        :type username: str
        :return: None
        """
        UsersDB.delete().where(UsersDB.username == username).execute()
        logging.debug(f"User {username} deleted from the Database.")

    def get_user_id(self, username):
        """
        Retrieves the user ID associated with the given username.

        This function queries the database to find the user whose username matches
        the provided parameter. If a match is found, the corresponding user ID is
        returned.

        :param username: The username of the user whose ID needs to be retrieved.
        :type username: str
        :return: The user ID corresponding to the provided username.
        :rtype: int
        """
        return UsersDB.select().where(UsersDB.username == username).get().user_id

    def check_username_against_password_hash(self, username, password_hash):
        """
        Checks if the provided password hash matches the stored password hash for the
        given username in the database.

        :param username: Username to look up in the database
        :type username: str
        :param password_hash: Hash of the password to compare with the stored value
        :type password_hash: str
        :return: True if the password hash matches the stored hash, False otherwise
        :rtype: bool
        """
        return UsersDB.select().where(UsersDB.username == username).get().password_hash == password_hash

    def does_user_exist(self, username):
        """
        Check if a user exists in the database.

        This method queries the UsersDB to determine if a specific user exists by
        matching the provided username.

        :param username: The username to check for existence in the database.
        :type username: str
        :return: A boolean value indicating whether the specified username exists
            in the database.
        :rtype: bool
        """
        return UsersDB.select().where(UsersDB.username == username).exists()

    def get_derived_key_salt(self, username):
        """
        Retrieves the derived key salt from the database for the given username.

        This method queries the `UsersDB` table to find a record matching the
        provided username and retrieves the `derived_key_salt` attribute. It
        is used for fetching the salt required in cryptographic operations.

        :param username: The username whose derived key salt is to be retrieved.
        :type username: str
        :return: The derived key salt associated with the given username.
        :rtype: str
        """
        return UsersDB.select().where(UsersDB.username == username).get().derived_key_salt

    def get_encrypted_master_key(self, username):
        """
        Fetches the encrypted master key associated with the specified username from the database.

        This method queries the database to locate a user record that matches the provided
        username and retrieves the `encrypted_master_key` field from that record. It assumes
        that the `username` exists in the database, and the corresponding record satisfies the
        condition specified in the query.

        :param username: The username of the user whose encrypted master key is to be retrieved.
        :type username: str

        :return: The encrypted master key associated with the given username.
        :rtype: Any
        """
        return UsersDB.select().where(UsersDB.username == username).get().encrypted_master_key

    def get_encrypted_master_key_nonce(self, username):
        """
        Retrieve the encrypted master key nonce for a given username.

        This method queries the `UsersDB` to find the encrypted master key nonce
        associated with the specified username. It assumes that the username
        exists in the database and raises an exception if no match is found.

        :param username: The username used to locate the encrypted master key nonce.
        :type username: str
        :return: The encrypted master key nonce for the specified username.
        :rtype: str
        """
        return UsersDB.select().where(UsersDB.username == username).get().encrypted_master_key_nonce

    def change_username(self, user_id, new_username):
        """
        Updates the username of a user in the database.

        This function updates the username of a specific user by their unique
        identifier in the database. The new username provided will replace
        the existing one associated with the user.

        :param user_id: Unique identifier of the user whose username is to be updated
        :param new_username: The new username to be assigned to the user
        :return: None
        """
        UsersDB.update(username=new_username).where(UsersDB.user_id == user_id).execute()

    def update_user_credentials(self, user_id, new_password_hash, new_derived_key_salt, new_encrypted_master_key, new_encrypted_master_key_nonce):
        """
        Updates the user's credentials in the database with new values. The function updates
        the password hash, derived key salt, encrypted master key, and the nonce associated
        with the encrypted master key for the specified user.

        :param user_id: The unique identifier of the user whose credentials are being updated.
        :type user_id: int
        :param new_password_hash: The new hash of the user's password.
        :type new_password_hash: str
        :param new_derived_key_salt: The new salt used for deriving the user's key.
        :type new_derived_key_salt: str
        :param new_encrypted_master_key: The new encrypted master key for the user.
        :type new_encrypted_master_key: str
        :param new_encrypted_master_key_nonce: The new nonce that was used to encrypt the master key.
        :type new_encrypted_master_key_nonce: str
        :return: None
        """
        UsersDB.update(
            password_hash=new_password_hash,
            derived_key_salt=new_derived_key_salt,
            encrypted_master_key=new_encrypted_master_key,
            encrypted_master_key_nonce=new_encrypted_master_key_nonce
        ).where(
            UsersDB.user_id == user_id
        ).execute()

