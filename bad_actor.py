#for the representation of mallory
import random
from Crypto.Hash import SHA3_256
from Crypto.Cipher import AES
from model import Model

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

    def alter_a(self, others: list[Model], new_a: int) -> None:
        for other in others:
            other.alpha = new_a
        self.alpha = new_a

    def intercept(self, recipient:Model):
        recipient.partner_partial = self.q

    def steal_iv(self, target:Model) -> None:
        self.iv = target.iv

    def steal_and_decrypt_msg(self, target:Model) -> str:
        msg = target.message
        if self.alpha == self.q:
            self.key = SHA3_256.new(bytes.fromhex("00")).digest()[0:16]
        elif self.alpha == 1:
            self.key = SHA3_256.new(bytes.fromhex("01")).digest()[0:16]
        elif self.alpha == self.q - 1:
            self.key = SHA3_256.new(bytes.fromhex("01")).digest()[0:16]
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        #note: ISO-8859-1 is used here due to issues with decoding using utf-8.
        return cipher.decrypt(msg).decode("ISO-8859-1")

