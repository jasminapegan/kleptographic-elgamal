from factordb.factordb import FactorDB
from Crypto.Cipher import AES
from math import sqrt


def is_generator(g, p):
    f = FactorDB(p-1)
    f.connect()
    factors = f.get_factor_list()
    for q in factors:
        e = pow(g, (p-1) // q, p)
        if e == 1:
            return False
    return True


def R1(x, k):
    return R2(x, k+1)


def R1_inverse(y, k):
    return R2_inverse(y, k+1)


def R2(x, k):
    x_bytes = x.to_bytes(256, byteorder='little')
    k %= 2 ** 32
    k_bytes = k.to_bytes(32, byteorder='little')
    aes = AES.new(k_bytes, AES.MODE_CFB, 16 * b'\x00')
    cipher = aes.encrypt(x_bytes)
    return int.from_bytes(cipher, byteorder='little')


def R2_inverse(y, k):
    y_bytes = y.to_bytes(256, byteorder='little')
    k %= 2 ** 32
    k_bytes = k.to_bytes(32, byteorder='little')
    aes = AES.new(k_bytes, AES.MODE_CFB, 16 * b'\x00')
    plaintext = aes.decrypt(y_bytes)
    return int.from_bytes(plaintext, byteorder='little')


def stddev(lst):
    avg = sum(lst) / len(lst)
    return sqrt(sum([(x - avg)**2 for x in lst]) / len(lst))


"""
def H(x):
    attacker_dict = read_file("attacker.json")
    attacker_elgamal = attacker_dict["elgamal"]
    x_bytes = x.to_bytes(256, byteorder='little')
    aes = AES.new(attacker_elgamal[1], AES.MODE_CFB, 16 * b'\x00')
    return int.from_bytes(aes.encrypt(x_bytes), byteorder='little')
"""
