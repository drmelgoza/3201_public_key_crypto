from Crypto.Util.number import getPrime

# find gcd using extended euclidean algorithm
def egcd(a: int, b: int):
    #Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e: int, phi: int) -> int:
    #Computes d such that (e * d) % phi == 1
    gcd, x, _ = egcd(e, phi)

    # if not valid values for e and phi chosen
    if gcd != 1:
        raise ValueError("e and phi are not coprime; inverse does not exist")
    return x % phi

# key generation
# e = 65537
def generate_keypair(prime_bits_size: int, e: int = 65537):
    p = getPrime(prime_bits_size)
    q = getPrime(prime_bits_size)

    n = p * q
    phi = (p - 1)(q - 1)
    d = mod_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key

# helper functions to convert messages to and from strings/ints
def str_to_int(message:str) -> int:
    return int.from_bytes(message.encode("utf-8"), byteorder = "big")

def int_to_str (int_message:int) -> str:
    byte_len = (int_message.bit_length() + 7)//8
    return int_message.to_bytes(byte_len, byteorder = "big").decode("utf-8")

def encrypt(message:int, public_key:tuple[int, int]) -> int:
    e = public_key[0]
    n = public_key[1]
    # message ^ e mod n
    return pow(message, e, n)

def decrypt(message:int, private_key:tuple[int, int]) -> int:
    d = private_key[0]
    n = private_key[1]
    # message ^ d mod n
    return pow(message, d, n)