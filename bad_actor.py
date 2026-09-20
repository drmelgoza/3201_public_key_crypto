#for the representation of mallory
import random
from Crypto.Hash import SHA3_256
from Crypto.Cipher import AES
from model import Model

def get_new_key(size: int = 128) -> bytes:
    key = random.getrandbits(size)
    byte_key = key.to_bytes(16)
    return byte_key

def add_padding(data: bytes) -> bytes:
    bytes_needed = 16 - (len(data) % 16)
    padding_template = bytes_needed.to_bytes(1) * bytes_needed
    return data + padding_template

class BadActor:
    def __init__(self):
        self.q : int = 0
        self.alpha : int = 0
        self.exp : int = 0
        self.partial_a : int = 0
        self.partial_b : int = 0
        self.s : int = 0
        self.key : bytes = int.to_bytes(0)
        self.iv : bytes = int.to_bytes(0)
        self.message : bytes = bytes()
        self.partner_message : bytes = bytes()

    def steal_q_and_a(self, other: Model) -> None:
        self.q = other.q
        self.alpha = other.alpha

    def intercept(self, recipient:Model):
        recipient.partner_partial = self.q

    def steal_iv(self, target:Model) -> None:
        self.iv = target.iv

    def steal_and_decrypt_msg(self, target:Model) -> str:
        msg = target.message
        self.key = SHA3_256.new(bytes.fromhex("00")).digest()[0:16]
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return cipher.decrypt(msg).decode("utf-8")