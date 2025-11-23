import jwt
import time

from jwt import DecodeError

from Dependencies.Constants import private_key, public_key


class TokensService:
    def __init__(self):
        self.private_key = private_key
        self.public_key = public_key

    def create_token(self, username):
        return jwt.encode({"username": username, "exp": int(time.time() + 10*60)}, self.private_key, algorithm="RS256") # 10 minutes

    def is_token_valid(self, token_to_validate):
        try:
            decoded_token = self.decode_token(token_to_validate)
            if decoded_token["exp"] > int(time.time()):
                return True
            else:
                return False
        except DecodeError:
            return False

    def does_token_need_refreshing(self, token_to_check):
        decoded_token = self.decode_token(token_to_check)
        if decoded_token["exp"] - 2*60 > int(time.time()): # 2 minutes
            return True
        else:
            return False

    def decode_token(self, token_to_decode):
        return jwt.decode(token_to_decode, self.public_key, algorithms=["RS256"])


if __name__ == "__main__":
    ts = TokensService()
    token = ts.create_token("qwe")
    print(token)
    print(ts.decode_token(token)["username"])