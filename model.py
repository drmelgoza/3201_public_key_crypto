#for the representation of Alice and Bob
import random
from Crypto.Hash import SHA3_256
from Crypto.Cipher import AES

def get_new_key(size: int = 128) -> bytes:
    key = random.getrandbits(size)
    byte_key = key.to_bytes(16)
    return byte_key

def add_padding(data: bytes) -> bytes:
    bytes_needed = 16 - (len(data) % 16)
    padding_template = bytes_needed.to_bytes(1) * bytes_needed
    return data + padding_template

class Model:
    def __init__(self):
        self.q : int = 0
        self.alpha : int = 0
        self.exp : int = 0
        self.partial_s : int = 0
        self.partner_partial : int = 0
        self.s : int = 0
        self.key : bytes = int.to_bytes(0)
        self.iv : bytes = int.to_bytes(0)
        self.message : bytes = bytes()
        self.partner_message : bytes = bytes()

    #function to generate q and a
    def set_q_and_a(self, q: int, a: int) -> None:
        #q must be a prime number
        self.q = q
        #alpha must be a number less than q
        self.alpha = a

    def send_q_and_a(self, other:Model) -> None:
        other.q = self.q
        other.alpha = self.alpha

    def set_partial_secret(self) -> None:
        #exponent must be less than q (technically the set of all numbers possible in a "mod q" operation")
        self.exp = random.randint(0, self.q)
        self.partial_s = int(pow(self.alpha, self.exp, self.q))

    def send_partial_s(self, other: Model) -> None:
        other.partner_partial = self.partial_s

    def set_secret_number(self) -> None:
        self.s = int(pow(self.partner_partial, self.exp, self.q))

    def set_key(self):
        hex_form = hex(self.s)[2:]
        if len(hex_form) == 1 and hex_form == "0":
            hex_form = hex_form + "0"
        self.key = SHA3_256.new(bytes.fromhex(hex_form)).digest()[0:16]

    def get_key(self) -> bytes:
        return self.key

    def set_and_share_iv(self, other: Model) -> None:
        self.iv = get_new_key()
        other.iv = self.iv

    def send_message(self, message_str: str, other: Model) -> None:
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_message = add_padding(message_str.encode("utf-8"))
        self.message = cipher.encrypt(padded_message)
        other.partner_message = self.message


    def get_partner_message(self) -> bytes:
        return self.partner_message

    def decrypt_message(self) -> str:
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.decrypt(self.partner_message).decode("utf-8")



