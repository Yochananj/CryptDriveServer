"""
Password Hashing Manager Module

This module provides secure password hashing and verification functionality for the
CryptDrive encrypted file storage system. It implements the Argon2 password hashing
algorithm, which is a modern, memory-hard key derivation function designed to resist
GPU-based and custom hardware attacks.

The module offers two primary functions:
- hash_password: Securely hashes plaintext passwords using Argon2 with customized
  parameters (time cost, memory cost, and parallelism) to provide strong protection
  against brute-force attacks.
- verify_password: Verifies that a plaintext password matches a previously hashed
  password, enabling secure authentication.

The Argon2 implementation uses the following parameters by default:
- Time cost: 3 iterations
- Memory cost: 64 MiB (65536 KiB)
- Parallelism: 4 threads

Dependencies:
    - argon2-cffi: Provides Python bindings for the Argon2 password hashing algorithm

Example usage:
    >>> from Services.PasswordHashingManager import hash_password, verify_password
    >>> hashed = hash_password("my_secure_password")
    >>> is_valid = verify_password("my_secure_password", hashed)
    >>> print(is_valid)
    True

This module is a critical component of the authentication and security infrastructure
within CryptDrive, ensuring that user passwords are stored and validated securely.
"""

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