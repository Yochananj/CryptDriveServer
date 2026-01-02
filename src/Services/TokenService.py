import time
from base64 import b64encode, b64decode

import jwt
from jwt import DecodeError

from Dependencies.Constants import private_key, public_key


class TokenService:
    def __init__(self):
        self.private_key = private_key
        self.public_key = public_key

    def create_login_token(self, username) -> str:
        return jwt.encode({"username": username, "exp": int(time.time() + 60*60)}, self.private_key, algorithm="RS256")
                                                                        # 60 minutes
    def create_encryption_token(self, encrypted_key, nonce) -> bytes:
        enc_token = jwt.encode({"encrypted_key": b64encode(encrypted_key).decode(), "exp": int(time.time() + 60 * 60), "nonce": b64encode(nonce).decode()}, self.private_key, algorithm="RS256").encode()
        return enc_token
                                                              # 60 minutes
    def is_token_valid(self, token_to_validate):
        try:
            decoded_token = self.decode_token(token_to_validate)
            if decoded_token["exp"] > int(time.time()):
                return True
            else:
                return False
        except DecodeError:
            return False

    def token_needs_refreshing(self, token_to_check):
        decoded_token = self.decode_token(token_to_check)
        if decoded_token["exp"] - 10*60 < int(time.time()):
            return True         # 10 minutes
        else:
            return False

    def decode_token(self, token_to_decode):
        if isinstance(token_to_decode, bytes):
            token_to_decode = token_to_decode.decode()
        return jwt.decode(token_to_decode, self.public_key, algorithms=["RS256"])


if __name__ == "__main__":
    ts = TokenService()
    token = ts.create_encryption_token(b"abcdefg", b"1234567890")
    print(token)
    print(b64decode(ts.decode_token(token)["encrypted_key"].encode()), b64decode(ts.decode_token(token)["nonce"].encode()))