import logging
import os
import peewee
from Dependencies.Constants import server_storage_path

db_path = os.path.join(server_storage_path, "Users.db")
users_db = peewee.SqliteDatabase(db_path)
os.makedirs(os.path.dirname(db_path), exist_ok=True)

class UsersDB(peewee.Model):
    user_id = peewee.AutoField()
    username = peewee.CharField()
    password_hash = peewee.CharField()
    derived_key_salt = peewee.BlobField()
    encrypted_master_key = peewee.BlobField()
    encrypted_master_key_nonce = peewee.BlobField()

    class Meta:
        database = users_db
        indexes = ((('username',),True),)

class UsersDatabaseDAO:
    def __init__(self):
        users_db.connect()
        logging.debug(f"Connected to the Database at {db_path}.")
        UsersDB.create_table([UsersDB])

    def create_user(self, username, password_hash, derived_key_salt, encrypted_file_master_key, encrypted_master_key_nonce):
        UsersDB.create(
            username=username,
            password_hash=password_hash,
            derived_key_salt=derived_key_salt,
            encrypted_master_key=encrypted_file_master_key,
            encrypted_master_key_nonce=encrypted_master_key_nonce
        )
        logging.debug(f"User {username} created in the Database (ID: {self.get_user_id(username)})")

    def delete_user(self, username):
        UsersDB.delete().where(UsersDB.username == username).execute()
        logging.debug(f"User {username} deleted from the Database.")

    def get_user_id(self, username):
        return UsersDB.select().where(UsersDB.username == username).get().user_id

    def check_username_against_password_hash(self, username, password_hash):
        return UsersDB.select().where(UsersDB.username == username).get().password_hash == password_hash

    def does_user_exist(self, username):
        return UsersDB.select().where(UsersDB.username == username).exists()

    def get_derived_key_salt(self, username):
        return UsersDB.select().where(UsersDB.username == username).get().derived_key_salt

    def get_encrypted_master_key(self, username):
        return UsersDB.select().where(UsersDB.username == username).get().encrypted_master_key

    def get_encrypted_master_key_nonce(self, username):
        return UsersDB.select().where(UsersDB.username == username).get().encrypted_master_key_nonce

    def change_username(self, user_id, new_username):
        UsersDB.update(username=new_username).where(UsersDB.user_id == user_id).execute()

    def update_user_credentials(self, user_id, new_password_hash, new_derived_key_salt, new_encrypted_master_key, new_encrypted_master_key_nonce):
        UsersDB.update(
            password_hash=new_password_hash,
            derived_key_salt=new_derived_key_salt,
            encrypted_master_key=new_encrypted_master_key,
            encrypted_master_key_nonce=new_encrypted_master_key_nonce
        ).where(
            UsersDB.user_id == user_id
        ).execute()

