from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pathlib import Path
import base64
import os
from xdg import xdg_data_home

APP_DIR = xdg_data_home() / Path("oathstore")
SALT_FILE = APP_DIR / Path("salt")
STORE = APP_DIR / Path("data.pbcrypt")


def hash_pwd(password: bytes):
    if not SALT_FILE.exists():
        salt = os.urandom(16)
        with open(SALT_FILE, mode="wb") as fd:
            fd.write(salt)
    else:
        with open(SALT_FILE, mode="rb") as fd:
            salt = fd.read()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def gen_key(hash: bytes):
    return Fernet(hash)


def encrypt_data(hash: bytes, data: bytes, outfile: Path):
    fernet = gen_key(hash)
    encrypted = fernet.encrypt(data)
    with open(outfile, mode="wb") as fd:
        fd.write(encrypted)


def decrypt_data(hash: str, infile: Path):
    fernet = gen_key(hash)
    with open(infile, mode="rb") as fd:
        e_data = fd.read()
        decrypted = fernet.decrypt(e_data)

        return decrypted


if __name__ == "__main__":
    if not APP_DIR.exists():
        print("Creating init file")
        os.makedirs(APP_DIR)
    password = b"test"
    hash = hash_pwd(password)
    test_data = b"0XDEADBEEF"
    encrypt_data(hash, test_data, STORE)
    hash_bis = hash_pwd(password)
    data = decrypt_data(hash_bis, STORE)
    print(data == test_data)
