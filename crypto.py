"""
Module dealing with all required cryptographic operations.
Provides a level of abstraction over these, through the use of the CryptoSystem children, each representing their own
available cryptographic algorithm
"""

from abc import ABC, abstractmethod
from typing import Self
from cryptography.hazmat.primitives.asymmetric.rsa import (RSAPublicKey, RSAPrivateKey,
                                                           generate_private_key as rsa_generate_private_key)
from cryptography.hazmat.primitives.asymmetric.ec import (EllipticCurvePublicKey, EllipticCurvePrivateKey,
                                                          generate_private_key as ec_generate_private_key, ECDSA,
                                                          EllipticCurve, SECP256R1, SECP384R1, SECP521R1, SECP224R1,
                                                          SECP192R1)
from cryptography.hazmat.primitives.serialization import (Encoding, PublicFormat, load_pem_private_key, PrivateFormat,
                                                          NoEncryption)
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256, HashAlgorithm
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.exceptions import InvalidSignature
from pathlib import Path

RSA_DEFAULT_PUBLIC_EXPONENT: int = 65537
"""The default public exponent (``e``) of the public key"""

SHA256: HashAlgorithm = _SHA256()
"""Shortcut to instance of Cryptography SHA256 class"""

VALID_ENCRYPTION_ALGORITHMS: list[str] = ["rsa2048", "rsa3072", "rsa4096", "ecdsa192", "ecdsa224", "ecdsa256",
                                          "ecdsa384", "ecdsa521"]
"""A list containing all valid encryption algorithms.  Used by ``argparse``, to ensure --algo is one of these options"""


def _int_to_bytes(byte_int: int) -> bytes:
    """
    Converts an ``int`` to a ``bytes`` object
    :param byte_int: the integer to convert
    :return: ``byte_int`` represented in ``bytes``
    """
    raw_hex: str = hex(byte_int)
    cleaned_hex: str = f"{'0' if len(raw_hex) % 2 != 0 else ''}{hex(byte_int)[2:]}"

    return bytes.fromhex(cleaned_hex)


def load_priv_key(key_bytes: bytes) -> EllipticCurvePrivateKey | RSAPrivateKey:
    """
    Loads a private key from the provided ``key_bytes``
    :param key_bytes: the bytes forming the private key
    :return: the private key described by ``key_bytes``
    """
    priv_key = load_pem_private_key(key_bytes, None)

    if isinstance(priv_key, (EllipticCurvePrivateKey, RSAPrivateKey)):
        return priv_key

    raise ValueError("The supplied private key is invalid for this program - must be RSA or Elliptic Curve (ECDSA).")


class CryptoSystem[PRIV_KEY: PrivateKeyTypes, PUB_KEY](ABC):
    """Abstract class representing a particular cryptographic algorithm"""

    def __init__(self, key_length: int, priv_key: PRIV_KEY, pub_key: PUB_KEY) -> None:
        self._key_len: int = key_length
        self._priv_key: PRIV_KEY = priv_key
        self._pub_key: PUB_KEY = pub_key

    @classmethod
    def with_generate_keys(cls, key_length: int) -> Self:
        """
        Constructor method to create new crypto system with generated keys
        :param key_length: the key length (in bits)
        :return: Self
        """
        priv_key, pub_key = cls.generate_keys(key_length)

        return cls(key_length, priv_key, pub_key)

    @classmethod
    def from_priv_key(cls, priv_key: PRIV_KEY) -> Self:
        """
        Constructor method to create new crypto system from pre-existing private key
        :param priv_key: the private key to use to create new crypto system
        :return: Self
        """
        pub_key: PUB_KEY = priv_key.public_key()
        return cls(priv_key.key_size, priv_key, pub_key)

    @property
    def priv_key(self):
        """Gets the private key stored by the Cryptosystem"""
        return self._priv_key

    @property
    def pub_key(self):
        """Gets the public key stored by the Cryptosystem"""
        return self._pub_key

    @classmethod
    @abstractmethod
    def generate_keys(cls, key_length: int) -> tuple[PRIV_KEY, PUB_KEY]:
        """Method for creating new crypto system with generated keys, specified by the key length"""
        ...

    @abstractmethod
    def generate_file_signature(self, file_hash: bytes) -> int:
        """Method for generating file signatures from the file hash and instance key-pair"""
        ...

    @abstractmethod
    def verify_signature(self, file_hash: bytes, expected_signature: int) -> bool:
        """Method for verifying the signature of the file hash, using the instance key-pair"""
        ...

    @classmethod
    def serialise_pub_key(cls, pub_key: PUB_KEY, pub_key_fp: Path, overwrite_path: bool) -> None:
        """
        Saves the public key to the file system
        :param pub_key: the public key to serialise
        :param pub_key_fp: the file path of where to dump the public key
        :param overwrite_path: whether or not to overwrite the file path, if a file already exists
        :return: None
        """

        if pub_key_fp.exists() and not overwrite_path:
            raise FileExistsError(
                f"File {pub_key_fp} already exists, but overwriting is not forced (do '--overwrite' to complete this action)"
            )

        with open(pub_key_fp, "wb") as file:
            file.write(pub_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ))


    @classmethod
    def serialise_priv_key(cls, priv_key: PRIV_KEY, priv_key_fp: Path, overwrite_path: bool) -> None:
        """
        Serialises the private key to the file system.
        :param priv_key: the private key to serialise
        :param priv_key_fp: the file path to the desired location of the private key
        :param overwrite_path: whether to overwrite a file already at this location, if already there
        :return: None
        """

        if priv_key_fp.exists() and not overwrite_path:
            raise FileExistsError(
                f"File {priv_key_fp} already exists, but overwriting is not forced (do '--overwrite' to complete this action)"
            )

        with open(priv_key_fp, "wb") as file:
            file.write(priv_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))

    def serialise_own_pub_key(self, pub_key_fp: Path, overwrite_path: bool = False) -> None:
        """Serialises the instance's own public key"""
        self.serialise_pub_key(self.pub_key, pub_key_fp, overwrite_path)

    @staticmethod
    def signature_as_bytes(signature: int) -> bytes:
        """Converts an integer file signature into the corresponding bytes"""
        return _int_to_bytes(signature)


class RSACryptoSystem(CryptoSystem[RSAPrivateKey, RSAPublicKey]):
    """CryptoSystem implementing RSA (asymmetric encryption algorithm)"""

    @classmethod
    def generate_keys(cls, key_length: int) -> tuple[RSAPrivateKey, RSAPublicKey]:
        """
        Generates an RSA key pair of length ``key_length``, with e = ``RSA_DEFAULT_PUBLIC_EXPONENT``
        :param key_length: the number of bits of the modulus and private key
        :return: the key pair in the form (priv_key, pub_key)
        """
        priv_key: RSAPrivateKey = rsa_generate_private_key(RSA_DEFAULT_PUBLIC_EXPONENT, key_length)
        return priv_key, priv_key.public_key()

    def generate_file_signature(self, file_hash: bytes) -> int:
        """
        Generates the RSA signature of the generated ``file_hash``
        :param file_hash: the SHA256 file hash
        :return: the generated file hash
        """

        private_exponent: int = self._priv_key.private_numbers().d
        modulus: int = self._priv_key.private_numbers().public_numbers.n

        return pow(int.from_bytes(file_hash), private_exponent, modulus)

    def verify_signature(self, file_hash: bytes, expected_signature: int) -> bool:
        """
        Calculates the signature check value from the signature and public key.
        To verify the signature, confirm this signature check value is equal to the file hash
        :param file_hash: the the file hash used to derive the signature
        :param expected_signature: the signature formed from the file hash and private key
        :return: whether the signature is correctly checked
        """
        public_exponent: int = self._pub_key.public_numbers().e
        modulus: int = self._pub_key.public_numbers().n

        hash_check: int = (pow(expected_signature, public_exponent, modulus))

        return hash_check == int.from_bytes(file_hash)


class EllipticCurveSystem(CryptoSystem[EllipticCurvePrivateKey, EllipticCurvePublicKey]):
    """CryptoSystem implementing ECDSA (Elliptic Curve Digital Signature Algorithm)"""

    CURVE_KEY_LENS: dict[int, type[EllipticCurve]] = {
        256: SECP256R1,
        384: SECP384R1,
        521: SECP521R1,
        224: SECP224R1,
        192: SECP192R1,
    }
    """Join dictionary, connecting the key length to the corresponding Elliptic Curve"""

    @classmethod
    def generate_keys(cls, key_length: int) -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        """
        Generate ECDA private and public keys of length ``key_length``
        :param key_length: the key size (and corresponding curve) to use
        :return: the key pair in the form (priv_key, pub_key)
        """
        curve: EllipticCurve = cls.CURVE_KEY_LENS[key_length]()

        priv_key: EllipticCurvePrivateKey = ec_generate_private_key(curve)
        return priv_key, priv_key.public_key()

    def generate_file_signature(self, file_hash: bytes) -> int:
        """
        Generates the ECDSA signature of the ``file_hash``
        :param file_hash: the file hash to generate the signature of
        :return: the file signature
        """
        return int.from_bytes(self.priv_key.sign(file_hash, ECDSA(Prehashed(SHA256))))

    def verify_signature(self, file_hash: bytes, expected_signature: int) -> bool:
        """
        Confirms the file signature correctly derives the file hash
        :param file_hash: the hash of the memory described the hex file
        :param expected_signature: the signature value calculated by the private key
        :return: whether the signatures match
        """
        try:
            self.pub_key.verify(_int_to_bytes(expected_signature), file_hash, ECDSA(Prehashed(SHA256)))
            return True
        except InvalidSignature:
            return False

