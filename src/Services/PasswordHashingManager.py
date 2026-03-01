import argon2

def hash_password(password: str) -> str:
    """
    Hashes a given password using the Argon2 algorithm. The function applies a high-memory
    and CPU-intensive hashing process ensuring a secure and computationally expensive
    derivation of the output hash. This makes brute-force attacks significantly harder.

    :param password: The plain-text password to be hashed.
    :type password: str
    :return: The Argon2-hashed representation of the given password.
    :rtype: str
    """
    return argon2.PasswordHasher(
        time_cost=3,
        memory_cost=64*1024, # 64 MiB
        parallelism=4
    ).hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verifies if a given plaintext password matches a previously hashed password using
    the Argon2 password hashing algorithm.

    This function is used to check the integrity of a password against its securely
    stored hash, ensuring that the plaintext password provided during a login or
    authentication attempt matches the expected value.

    :param password: The plaintext password provided by the user.
    :type password: str
    :param hashed_password: The securely hashed password to compare against.
    :type hashed_password: str
    :return: A boolean value indicating whether the plaintext password matches
        the hashed password.
    :rtype: bool
    """
    return argon2.PasswordHasher().verify(hashed_password, password)