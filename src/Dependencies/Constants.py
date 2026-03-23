import os
import platformdirs
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
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

# Server Constants:
server_storage_path = platformdirs.user_data_path(app_name)

## Token Constants:
access_token_lifetime = 15*60
refresh_token_lifetime = 12*60*60
encryption_token_lifetime = 30*60
token_needs_refreshing_lifetime = 5*60

# Server Keys
dependencies_dir = os.path.dirname(os.path.abspath(__file__))
PUBLIC_KEY_PATH = os.path.join(dependencies_dir, "public.pem")
PRIVATE_KEY_PATH = os.path.join(dependencies_dir, "private.pem")

with open(PUBLIC_KEY_PATH, "r") as file:
    public_key = file.read()

with open(PRIVATE_KEY_PATH, "r") as file:
    private_key = file.read()


# Code for generating a key pair for signing tokens on startup:

"""
startup_generated_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
startup_generated_public_key = startup_generated_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
startup_generated_private_key = startup_generated_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

for line in startup_generated_private_key.splitlines() + ["\n"] + startup_generated_public_key.splitlines():
    print(line)
"""

