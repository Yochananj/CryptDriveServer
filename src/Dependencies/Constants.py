import os
import platformdirs

# Constants:

# Project Constants
app_name = "CryptDrive"
app_author = "YochananJulian"

# Communication Flags
separator = "|||"
byte_data_flag = b"||| BYTE DATA |||"
string_data_flag = b"||| STRING DATA |||"
end_flag = b"||| END |||"

# Encryption Flags
init_flag = b"(&) INIT (&)"
resume_flag = b"(&) RESUME (&)"
encryption_separator = b"(&) SEP (&)"

# Common Constants
server_address = "0.0.0.0"
server_port = 8081
host_addr = (server_address, server_port)

buffer_size = 1024

# Server-Only Constants:
server_storage_path = platformdirs.user_data_path(app_name)

# Server Keys
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # directory in which this Constants.py file sits
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "public.pem")
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "private.pem")

with open(PUBLIC_KEY_PATH, "r") as file:
    public_key = file.read()

with open(PRIVATE_KEY_PATH, "r") as file:
    private_key = file.read()
