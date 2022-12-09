import time
import struct
import hashlib
import base64
from hmac import HMAC


class OATH:
    """An OATH generating class. This class updates the hotp value when necessary,
    allowing it to be used easily in a client.
    """
    def __init__(self, key: str, hotp_value: int = None, size=8):
        # Init variables
        self.size = size
        self.key = key
        self.key_b = None
        self.hotp_value = hotp_value
        self.hotp_value_b = None

        # Clean data and generate initial keys
        self.clean_key()
        self.pad_key()
        self.update_hotp_value_b()

    def update_hotp_value_b(self):
        if (
            tmp := struct.pack(">q", self.hotp_value or int(time.time() / 30))
        ) != self.hotp_value_b or not self.hotp_value_b:
            self.hotp_value_b = tmp

    def clean_key(self):
        self.key.replace(" ", "")

    def pad_key(self):
        padding_size = (self.size - (len(self.key) % self.size)) % self.size
        padding = "=" * padding_size
        self.key_b = base64.b32decode(self.key + padding, casefold=True)

    def hmac(self):
        mac = HMAC(key=self.key_b, msg=self.hotp_value_b, digestmod=hashlib.sha1)
        return mac.digest()

    def gen_code(self):
        self.update_hotp_value_b()
        hmac = self.hmac()
        cut = hmac[-1] & 0x0F
        val = (struct.unpack(">L", hmac[cut : cut + 4])[0] & 0x7FFFFFFF) % 1000000
        return f"{val:6d}"

    def __repr__(self):
        return f"OATH({self.key}, {self.hotp_value}, {self.size})"


if __name__ == "__main__":
    oath = OATH("5T6UVD2LS7ROL6CIPQWPVNL5QUGCNBIFZW5LJZBDDRNRIK6G3IXULF22NYUMUCOG")
    code_1 = oath.gen_code()
    print(code_1)
    oath_2 = OATH("YAAXB5T7ME2UMOINL3CNTUNGMZCIDVF33Z2PJYSYE6BSL7MOS562WZHQ7XZ7JFP4", 133)
    code_2 = oath_2.gen_code()
