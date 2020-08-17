from Crypto.Util import number
from Crypto.Random import random
from helpers import is_generator


def init_elgamal(k=2048):
    p = number.getStrongPrime(k)
    # print("p:", p)
    g = random.StrongRandom().randint(1, p)
    while not is_generator(g, p):
        g = random.StrongRandom().randint(1, p)
    # print("g:", g)
    return p, g


def keygen(p, g):
    x = random.StrongRandom().randint(1, p-1)
    y = pow(g, x, p)
    return y, x


def keygen_with_new_g(p, g):
    g = random.StrongRandom().randint(1, p)
    while not is_generator(g, p):
        g = random.StrongRandom().randint(1, p)
    x = random.StrongRandom().randint(1, p-1)
    y = pow(g, x, p)
    return y, x, g


def encrypt(m, key, p, g):
    k = random.StrongRandom().randint(1, p-1)
    r = pow(g, k, p)
    s = m * pow(key, k, p) % p
    return r, s


def decrypt(r, s, x, p):
    return s * pow(r, -x, p) % p


def sign(m, x, p, g):
    k = random.StrongRandom().randint(1, p - 2)
    while number.GCD(k, p-1) != 1:
        k = random.StrongRandom().randint(1, p - 2)

    r = pow(g, k, p)
    s = pow(k, -1, p-1) * (m - x*r) % (p - 1)
    return m, r, s


def verify(m, r, s, y, p, g):
    return pow(g, m, p) == pow(y, r, p) * pow(r, s, p) % p
