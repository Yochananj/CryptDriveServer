import time
from base64 import b64encode

import jwt
from jwt import DecodeError

from Dependencies.Constants import private_key, public_key, access_token_lifetime, refresh_token_lifetime, \
    encryption_token_lifetime, token_needs_refreshing_lifetime


class TokensService:
    """
    Provides functionality for generating, validating, and decoding JWT tokens.

    The `TokenService` class is designed to handle the creation and validation of JSON Web Tokens
    (JWT) for authentication and encryption purposes. It includes methods for issuing login tokens,
    processing encryption tokens, and checking token validity and refresh requirements. The tokens
    generated use the RS256 signing algorithm and include expiration times.

    :ivar private_key: The private key used for signing JWT tokens.
    :type private_key: Any
    :ivar public_key: The public key used for verifying JWT tokens.
    :type public_key: Any
    """
    def __init__(self):
        """
        Represents the initialization of a class with provided cryptographic keys.

        This class initializes with a private and public key, which may be utilized
        to handle cryptographic operations or key management functionalities. The
        exact operations are determined by the implementation details outside of this
        constructor.
        """
        self.private_key = private_key
        self.public_key = public_key

    def create_access_token(self, username) -> str:
        """
        Generates a JWT token for user authentication.

        This method creates a login token with an encoded payload containing the
        username and an expiration time of 10 minutes from the current timestamp.

        :param username: The username of the user for whom the token is being generated.
        :type username: str
        :return: A signed JWT token as a string.
        :rtype: str
        """
        return jwt.encode({"username": username, "exp": int(time.time() + access_token_lifetime)}, self.private_key, algorithm="RS256")


    def create_refresh_token(self, username: str) -> str:
        """
        Generates a JWT refresh token for a given username.

        The method creates a secure, time-limited refresh token encoded using the RS256 algorithm.
        The token will include the username, a flag indicating it is a refresh token, and an
        expiration timestamp set to 12 hours from the time of generation.

        Parameters:
        username (str): The username to include in the token payload.

        Returns:
        str: A JWT refresh token as a string.
        """
        return jwt.encode({"username": username, "refresh": True, "exp": int(time.time() + refresh_token_lifetime)}, self.private_key, algorithm="RS256")


    def create_encryption_token(self, encrypted_key, nonce) -> bytes:
        """
        Generates an encryption token using the given encrypted key and nonce. The token
        is a JWT that includes the encrypted key, a nonce, and an expiration time of
        60 minutes from the time it was created. The token is signed using the instance's
        private key with the RS256 algorithm. The encrypted key and nonce are base64
        encoded before being included in the token.

        :param encrypted_key: The encrypted key to include in the token.
        :type encrypted_key: bytes
        :param nonce: A nonce value to include in the token.
        :type nonce: bytes
        :return: A JWT token encoded as bytes.
        :rtype: bytes
        """
        enc_token = jwt.encode({"encrypted_key": b64encode(encrypted_key).decode(), "exp": int(time.time() + encryption_token_lifetime), "nonce": b64encode(nonce).decode()}, self.private_key, algorithm="RS256").encode()
        return enc_token

    def is_token_valid(self, token_to_validate):
        """
        Validates the provided token to check its expiration status.

        The method decodes the given token and determines if it has not
        yet expired based on the current time. If the token is correctly
        decoded and its expiration timestamp has not elapsed, it is
        considered valid. Otherwise, it is deemed invalid.

        :param token_to_validate: The token string that needs to be validated.
        :type token_to_validate: str
        :return: True if the token is valid (not expired), otherwise False.
        :rtype: bool
        """
        try:
            decoded_token = self.decode_token(token_to_validate)
            if decoded_token["exp"] > int(time.time()):
                return True
            else:
                return False
        except DecodeError:
            return False

    def is_refresh_token(self, token_to_validate):
        """
        Determines if a given token is a refresh token.

        This method validates the provided token to check if it is marked as a refresh
        token. If the decoding process fails due to an invalid token structure or missing
        fields, the method will return False.

        Args:
            token_to_validate (str): The JWT token string to validate.

        Returns:
            bool: True if the token is a valid refresh token, False otherwise.

        Raises:
            DecodeError: If the token cannot be decoded.
            KeyError: If the required fields are missing in the decoded token.
        """
        try:
            decoded_token = self.decode_token(token_to_validate)
            if decoded_token["refresh"]:
                return True
            else:
                return False
        except DecodeError | KeyError:
            return False

    def token_needs_refreshing(self, token_to_check):
        """
        Determine whether a token requires refreshing based on its expiration time.

        This method decodes a provided token and calculates if there are fewer than
        10 minutes remaining before the token's expiration. If so, it indicates that
        the token needs to be refreshed.

        :param token_to_check: The token to evaluate for potential refreshing.
        :type token_to_check: str
        :return: A boolean indicating whether the token needs to be refreshed.
        :rtype: bool
        """
        decoded_token = self.decode_token(token_to_check)
        if decoded_token["exp"] - token_needs_refreshing_lifetime < int(time.time()):
            return True
        else:
            return False

    def decode_token(self, token_to_decode):
        """
        Decodes a given JSON Web Token (JWT) using the RS256 algorithm and a public key.
        This method is designed to verify and parse a token into its components.

        :param token_to_decode: The JWT that needs to be decoded. It may be provided as
            a string or bytes.
        :type token_to_decode: str | bytes
        :return: A dictionary containing the decoded payload of the token.
        :rtype: dict
        """
        if isinstance(token_to_decode, bytes):
            token_to_decode = token_to_decode.decode()
        return jwt.decode(token_to_decode, self.public_key, algorithms=["RS256"])
