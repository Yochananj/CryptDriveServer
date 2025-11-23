import logging
import os
import peewee
from Dependencies.Constants import server_storage_path

db_path = os.path.join(server_storage_path, "Users.db")
users_db = peewee.SqliteDatabase(db_path)

class UsersDB(peewee.Model):
    user_id = peewee.AutoField()
    username = peewee.CharField()
    password_hash = peewee.CharField()

    class Meta:
        database = users_db
        indexes = ((('username',),True),)

class UsersDatabaseDAO:
    def __init__(self):
        users_db.connect()
        logging.debug(f"Connected to the Database at {db_path}.")
        UsersDB.create_table([UsersDB])

    def create_user(self, username, password_hash):
        UsersDB.create(username=username, password_hash=password_hash)
        logging.debug(f"User {username} created in the Database (ID: {self.get_user_id(username)})")

    def delete_user(self, username):
        UsersDB.delete().where(UsersDB.username == username).execute()
        logging.debug(f"User {username} deleted from the Database.")

    def get_user_id(self, username):
        user_id = UsersDB.select().where(UsersDB.username == username).get().user_id
        return user_id

    def check_username_against_password_hash(self, username, password):
        return UsersDB.select().where(UsersDB.username == username).get().password_hash == password

    def does_user_exist(self, username):
        return UsersDB.select().where(UsersDB.username == username).exists()

    def close_db(self):
        users_db.close()



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    users_dao = UsersDatabaseDAO()
    users_dao.create_user("yocha", "123123123123")