import logging
import os

from Dependencies.Constants import server_storage_path


class FilesDiskDAO:
    """
    Handles file storage and retrieval on disk.

    This class provides mechanisms for writing, retrieving, deleting, and
    managing files stored on disk. It is designed to organize files by their
    owner ID and unique identifier (UUID) within a defined storage path.
    """
    def __init__(self):
        pass

    def write_file_to_disk(self, file_owner_id, file_uuid, file_contents):
        """
        Writes the provided file contents to a specified location on disk after ensuring the directory
        structure exists. The file is saved uniquely using the combination of its owner ID and UUID.

        :param file_owner_id: Identifier for the owner of the file.
        :type file_owner_id: int
        :param file_uuid: Universally unique identifier for the file.
        :type file_uuid: str
        :param file_contents: Binary content to be written to the file.
        :type file_contents: bytes
        :return: None
        """
        os.makedirs(os.path.join(server_storage_path, str(file_owner_id)), exist_ok=True)
        full_file_path = self._get_full_file_path(file_owner_id, file_uuid)
        with open(full_file_path, "xb") as file:
            file.write(file_contents)
        logging.debug(f"File {full_file_path} written to disk.")

    def get_file_size_on_disk(self, file_owner_id, file_uuid):
        """
        Determines the file size on disk for a given file owned by a specific user.

        This function calculates and returns the size of a file located on
        the disk, identified by the owner ID and the file's unique identifier.
        The file's path is resolved using the `get_full_file_path` method.

        :param file_owner_id: The ID of the owner of the file.
        :type file_owner_id: Any
        :param file_uuid: The unique identifier of the file.
        :type file_uuid: Any
        :return: The file size in bytes.
        :rtype: int
        """
        full_file_path = self._get_full_file_path(file_owner_id, file_uuid)
        return os.path.getsize(full_file_path)

    def get_file_contents(self, file_owner_id, file_uuid):
        """
        Retrieve the contents of a specified file.

        This method locates a file based on the provided owner ID and file UUID,
        reads its contents in binary mode, and returns the data.

        :param file_owner_id: Unique identifier of the file owner.
        :type file_owner_id: str
        :param file_uuid: Unique identifier of the file.
        :type file_uuid: str
        :return: The binary contents of the specified file.
        :rtype: bytes
        """
        logging.debug(f"Getting file contents from {file_owner_id}/{file_uuid}.")
        full_file_path = self._get_full_file_path(file_owner_id, file_uuid)
        with open(full_file_path, "rb") as file:
            file_contents = file.read(-1)
        return file_contents

    def delete_file_from_disk(self, file_owner_id, file_uuid):
        """
        Deletes a file from disk for the specified file owner and file identifier.

        This method removes a file associated with a given owner and file UUID. It
        utilizes the full file path constructed based on the provided parameters
        to locate and delete the file from disk.

        :param file_owner_id: Identifier of the file owner
        :type file_owner_id: int
        :param file_uuid: Unique identifier of the file
        :type file_uuid: str
        :return: None
        """
        os.remove(self._get_full_file_path(file_owner_id, file_uuid))

    def _get_full_file_path(self, file_owner_id, file_uuid):
        """
        Constructs and returns the full file path by combining the specified server storage
        path, the provided file owner's identifier, and the file's unique identifier. The
        method ensures proper structuring of the file path for accessibility and storage.

        :param file_owner_id: The unique identifier of the file owner.
        :type file_owner_id: int

        :param file_uuid: The unique identifier of the file.
        :type file_uuid: str

        :return: The complete file path as a string that can be used for accessing or storing
            the file in the server's storage system.
        :rtype: str
        """
        return os.path.join(server_storage_path, str(file_owner_id), str(file_uuid))

