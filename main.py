"""File-Signer CLI tool"""

from hex_parser import parse_hex_file
from crypto import (RSACryptoSystem, RSAPublicKey, RSAPrivateKey, EllipticCurvePublicKey, EllipticCurvePrivateKey,
                    EllipticCurveSystem, CryptoSystem, VALID_ENCRYPTION_ALGORITHMS, load_priv_key)
from hashlib import sha256
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import Optional


class UnableToVerifySignatureException(Exception):
    """Exception raised when the file signature verification check fails"""

    def __init__(self) -> None:
        super().__init__("Unable to verify the generated signature (signature check != file hash).")


def hex_file_get_hash(fp: Path, pad_start: bool, hex_dump_fp: Optional[Path]) -> bytes:
    """
    Gets the SHA256 hash of the file at ``fp``
    :param fp: the file path of the file to hash
    :param pad_start: whether or not to pad the start of the .hex ``bytes`` down to address 0
    :param hex_dump_fp: the file path to dump the contents of the hex file to.  If None, hex file is not dumped
    :return: the SHA256 hash of ``fp``
    """
    with open(fp, "r") as file:
        file_bytes: bytes = parse_hex_file(file.read(), pad_start, hex_dump_fp)
        return sha256(file_bytes).digest()


def get_cryptosystem(algorithm_name: str, priv_key_fp: Path | None) -> CryptoSystem:
    """
    Gets a CryptoSystem instance from the ``algorithm_name`` and ``priv_key_fp``
    :param algorithm_name: the name of the signing algorithm to use
    :param priv_key_fp: the file path of the private key, if provided (if not, a new one will be generated)
    :return: the CryptoSystem
    """
    if priv_key_fp is not None:
        with open(priv_key_fp, "rb") as file:
            priv_key: EllipticCurvePrivateKey | RSAPrivateKey = load_priv_key(file.read())

        if isinstance(priv_key, EllipticCurvePrivateKey):
            return EllipticCurveSystem.from_priv_key(priv_key)

        if isinstance(priv_key, RSAPrivateKey):
            return RSACryptoSystem.from_priv_key(priv_key)

        raise NotImplementedError

    if algorithm_name.startswith("rsa"):
        key_length: int = int(algorithm_name.strip("rsa"))
        crypto_system_type = RSACryptoSystem
    elif algorithm_name.startswith("ecdsa"):
        key_length: int = int(algorithm_name.strip("ecdsa"))
        crypto_system_type = EllipticCurveSystem
    else:
        raise NotImplementedError

    return crypto_system_type.with_generate_keys(key_length)


def compute_signature_and_key_pair(fp: Path, algorithm_name: str, priv_key_fp: Path | None, hex_pad_start: bool,
                                   hex_dump_fp: str | None) \
        -> tuple[int, RSAPrivateKey | EllipticCurvePublicKey, RSAPublicKey | EllipticCurvePublicKey]:
    """
    Computes the correct file signature and RSA public key.  Also internally validates that the public key correctly
    verifies the signature
    :param fp: the Path to the file path
    :param algorithm_name: the algorithm name to use for the signature generation and verification, passed from CLI args
    :param priv_key_fp: the file path to the private key
    :param hex_pad_start: whether or not to pad the .hex memory buffer to address 0
    :param hex_dump_fp: the file path to dump the hex file contents to.   If None, hex file is not dumped
    :return: file signature and RSA Public Key, in form (file_signature, rsa_public_key)
    """

    file_hash: bytes = hex_file_get_hash(fp, hex_pad_start, Path(hex_dump_fp) if hex_dump_fp is not None else None)

    cryptosystem: CryptoSystem = get_cryptosystem(algorithm_name, priv_key_fp)

    file_signature: int = cryptosystem.generate_file_signature(file_hash)

    if not cryptosystem.verify_signature(file_hash, file_signature):
        raise UnableToVerifySignatureException

    with open(f"{str(fp)}.sign", "wb") as file:
        file.write(cryptosystem.signature_as_bytes(file_signature))

    return file_signature, cryptosystem.priv_key, cryptosystem.pub_key


def main() -> int:
    """Main entrypoint to program."""

    arg_parser: ArgumentParser = ArgumentParser(
        prog="file-signer",
        description="Utility tool to sign the memory described by a .hex file",
        exit_on_error=True
    )

    arg_parser.add_argument("fp", help="File path to read from.")
    arg_parser.add_argument("-priv-key-fp", "-priv-key",
                            help="The file path to the private key to use to generate file signature "
                                 "(default is to generate a new key-pair)")
    arg_parser.add_argument("--pad-start", "-ps", action="store_true",
                            help="Pad the start of the .hex memory, down to address 0")
    arg_parser.add_argument("--algo", "-a", "--algorithm", help="Encryption algorithm to use for file signature",
                            choices=VALID_ENCRYPTION_ALGORITHMS, default="rsa2048")
    arg_parser.add_argument("-pub-key-out", "-pub-ko", help="File path to dump public key to", default="pubkey.pem")
    arg_parser.add_argument("-priv-key-out", "-priv-ko", help="File path to dump private key to", default="privkey.pem")
    arg_parser.add_argument("--overwrite-key", action="store_true",
                            help="Force overwrite of key file(s), if files already exist at file path")
    arg_parser.add_argument("--dump-hex-contents-fp", "-hex-fp", default=None,
                            help="File path to dump the contents of the described memory from the hex file")

    arg_namespace: Namespace = arg_parser.parse_args()

    hex_fp: Path = Path(arg_namespace.fp)

    if not hex_fp.exists():
        raise FileNotFoundError(f"Cannot sign '{hex_fp.name}', as it is not a valid file")

    if not hex_fp.suffix == ".hex":
        raise ValueError(
            f"Only .hex files can be signed with this program - {hex_fp.name} is not a .hex file "
            f"('{hex_fp.suffix}' != '.hex')"
        )

    existing_priv_key_fp: Path | None = Path(arg_namespace.priv_key_fp) \
        if arg_namespace.priv_key_fp is not None else None

    if existing_priv_key_fp is not None:
        print("Private key provided, so inferring encryption algorithm...")

    file_signature, priv_key, pub_key = compute_signature_and_key_pair(hex_fp, arg_namespace.algo, existing_priv_key_fp,
                                                                       arg_namespace.pad_start,
                                                                       arg_namespace.dump_hex_contents_fp)

    if existing_priv_key_fp is None:
        RSACryptoSystem.serialise_priv_key(priv_key, Path(arg_namespace.priv_key_out), arg_namespace.overwrite_key)

    RSACryptoSystem.serialise_pub_key(pub_key, Path(arg_namespace.pub_key_out), arg_namespace.overwrite_key)

    print("File signature generated successfully.")

    return 0


if __name__ == '__main__':
    quit(main())
