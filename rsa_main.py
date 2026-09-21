from rsa import *
from model import *
from bad_actor import *
from Crypto.Hash import SHA3_256
from Crypto.Cipher import AES

def main():
    # Alice generates key pair for RSA encryption
    pub, priv = generate_keypair(512)

    # Bob chooses number and encrypts secret
    s = 15
    c = encrypt(s, pub)

    # Mallory manipulates c to different value that she knows
    r = 1
    c_prime = encrypt(r, pub)

    # Alice recieves manipulated message and decrypts manipulated value
    s_alice = decrypt(c_prime, priv)

    alice = Model()
    bob = Model()
    mallory = BadActor()

    # Turn an integer secret into a 16-byte AES key.
    # Both Alice and Mallory must use this exact same process.
    def derive_aes_key(secret: int) -> bytes:
        secret_bytes = secret.to_bytes(
            (secret.bit_length() + 7) // 8,
            byteorder="big"
        )
        return SHA3_256.new(secret_bytes).digest()[:16]

    # Alice uses the secret she decrypted from c_prime.
    # This is r = 1 because Mallory substituted the ciphertext.
    alice.key = derive_aes_key(s_alice)

    # Bob still thinks the shared secret is his original s = 15.
    bob.key = derive_aes_key(s)

    print(f"Bob's intended secret: {s}")
    print(f"Alice's received secret: {s_alice}")
    print(f"Mallory's known secret: {r}")

    # Alice sends an AES-CBC message.
    # The IV is normally transmitted with the ciphertext, so Mallory can see it.
    alice.set_and_share_iv(bob)
    mallory.steal_iv(alice)

    m0 = "Hi Bob!"
    alice.send_message(m0, bob)

    print(f"Alice's AES key:   {alice.key.hex()}")
    print(f"Bob's AES key:     {bob.key.hex()}")  # Different: Bob cannot decrypt correctly.

    # Mallory derives the same key as Alice because she chose r.
    mallory_key = derive_aes_key(r)

    # Mallory decrypts Alice's captured ciphertext herself.
    cipher = AES.new(mallory_key, AES.MODE_CBC, mallory.iv)
    padded_plaintext = cipher.decrypt(alice.message)

    # Remove the PKCS#7-style padding added by Model.add_padding().
    padding_length = padded_plaintext[-1]
    recovered_m0 = padded_plaintext[:-padding_length].decode("utf-8")

    print(f"Mallory's AES key: {mallory_key.hex()}")
    print(f"Mallory recovered m0: {recovered_m0}")

    assert alice.key == mallory_key
    assert alice.key != bob.key
    assert recovered_m0 == m0

if __name__ == '__main__':
    main()