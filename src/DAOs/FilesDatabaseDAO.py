import logging
import peewee
import os
from Dependencies.Constants import server_storage_path

db_path = os.path.join(server_storage_path, "Files.db")
files_db = peewee.SqliteDatabase(db_path)
# shared_db_path = os.path.join(server_storage_path, "SharedFiles.db")
# shared_files_db = peewee.SqliteDatabase(shared_db_path)

class FilesDB(peewee.Model):
    file_id = peewee.AutoField()
    file_owner_id = peewee.IntegerField()
    user_file_path = peewee.CharField(null=True)
    user_file_name = peewee.CharField()
    file_uuid = peewee.CharField(null=True)
    file_size = peewee.IntegerField(default=0)
    file_nonce = peewee.BlobField(null=True)
    is_directory = peewee.BooleanField(default=False)

    class Meta:
        database = files_db
        indexes = (
        (("file_owner_id", "user_file_path", "user_file_name", "is_directory"), True),)

# class FilesSharedDB(peewee.Model):
#     share_id = peewee.AutoField()
#     file_owner_id = peewee.IntegerField()
#
#
#     class Meta:
#         database = files_db
#         indexes = (
#             (("file_owner_id", "user_file_path", "user_file_name", "is_directory"), True),)


class FilesDatabaseDAO:
    def __init__(self):
        files_db.connect()
        logging.debug(f"Connected to the Database at {db_path}.")
        files_db.create_tables([FilesDB])

    def create_file(self, file_owner_id, user_file_path, file_uuid, user_file_name, file_size, file_nonce):
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
        FilesDB.delete().where(
            FilesDB.user_file_name == user_file_name,
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == user_file_path
        ).execute()
        logging.debug(f"File {user_file_name} deleted from {file_owner_id}/{user_file_path} in the Database.")

    def create_dir(self, file_owner_id, user_file_path, user_file_name):
        FilesDB.create(
            file_owner_id=file_owner_id,
            user_file_path=user_file_path,
            user_file_name=user_file_name,
            is_directory=True
        )
        logging.debug(f"Directory {user_file_name} created in {file_owner_id}/{user_file_path} in the Database.")

    def delete_dir(self, file_owner_id, user_dir_path, user_dir_name):
        FilesDB.delete().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_name == user_dir_name,
            FilesDB.user_file_path == user_dir_path,
            FilesDB.is_directory == True
        ).execute()
        logging.debug(f"Directory {user_dir_name} deleted from {file_owner_id}/{user_dir_path} in the Database.")

    def get_file_uuid(self, file_owner_id, user_file_path, user_file_name):
        return FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == user_file_path,
            FilesDB.user_file_name == user_file_name,
            FilesDB.is_directory == False
        ).get().file_uuid

    def does_file_exist(self, file_owner_id, user_file_path, user_file_name):
        return FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == user_file_path,
            FilesDB.user_file_name == user_file_name,
            FilesDB.is_directory == False
        ).exists()

    def get_all_files_in_path(self, file_owner_id, path):
        return list(FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == path,
            FilesDB.is_directory == False
        ))

    def get_all_dirs_in_path(self, file_owner_id, path):
        return list(FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == path,
            FilesDB.is_directory == True
        ))

    def get_item_count_for_dir(self, file_owner_id, path):
        return len(list(FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == path,
        )))

    def does_dir_exist(self, file_owner_id, dir_path, dir_name):
        return FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == dir_path,
            FilesDB.user_file_name == dir_name,
            FilesDB.is_directory == True
        ).exists()

    def rename_and_move_file(self, file_owner_id, old_user_file_path, new_user_file_path, old_user_file_name, new_user_file_name):
        FilesDB.update(user_file_path=new_user_file_path, user_file_name=new_user_file_name).where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == old_user_file_path,
            FilesDB.user_file_name == old_user_file_name,
            FilesDB.is_directory == False
        ).execute()

    def rename_and_move_dir(self, file_owner_id, old_user_file_path, new_user_file_path, old_user_file_name, new_user_file_name):
        FilesDB.update(user_file_path=new_user_file_path, user_file_name=new_user_file_name).where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == old_user_file_path,
            FilesDB.user_file_name == old_user_file_name,
            FilesDB.is_directory == True
        ).execute()

    def get_file_nonce(self, file_owner_id, user_file_path, user_file_name):
        return FilesDB.select().where(
            FilesDB.file_owner_id == file_owner_id,
            FilesDB.user_file_path == user_file_path,
            FilesDB.user_file_name == user_file_name,
            FilesDB.is_directory == False
        ).get().file_nonce


    def close_db(self):
        files_db.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    dao = FilesDatabaseDAO()
    for file in dao.get_all_dirs_in_path(123, '/a'):
        print(file.user_file_path)
    files_db.close()