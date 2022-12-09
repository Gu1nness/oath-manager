# Copyleft: Neha Oudin
# GLPv3

from oath import OATH
from pathlib import Path
from configparser import ConfigParser

class OATHStore(dict):
    def __setitem__(self, key, value):
        super().__setitem__(key, OATH(value))

    def load(self, data: str):
        config = ConfigParser(allow_no_value=True)
        config.read_string(data)
        for section in config.sections():
            self.__setitem__(section, config.get(section, "key"))

    def load_from_file(self, path: Path):
        with open(path, mode="r") as fd:
            data = fd.read()
            self.load(data)

    def gen_code(self, entry: str):
        oath = self.__getitem__(entry)
        if not oath:
            return
        else:
            return oath.gen_code()


if __name__ == "__main__":
    oath_store = OATHStore()
    oath_store.load_from_file(Path("/home/noudin/.aws/.secrets"))
    print(oath_store)
    code = oath_store.gen_code("mfa-stg")
    print(code)
