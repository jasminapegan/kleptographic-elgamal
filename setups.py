from helpers import *
from Crypto.Util import number
from Crypto.Random import random
from storage import *


def elgamal_keygen_setup(p=None):
    # print("elgamal keygen setup")
    if p is None:
        p = number.getStrongPrime(2048)
    device_dict = read_file("files/device.json")
    B1, B2 = 16, 512
    E, N = device_dict["rsa_e"], device_dict["rsa_n"]
    K = device_dict["K"]
    x1 = N

    while x1 >= N:
        x = random.StrongRandom().randint(1, p-1)
        i = 0

        while i < B1 and x1 >= N:
            x1 = R1(x, K+i)
            if x1 >= N:
                i += 1

    x2 = pow(x1, E, N)
    j = 0

    while j < B2:
        x3 = R2(x2, K+j)
        if x3 < p and is_generator(x3, p):
            g = x3
            y = pow(g, x, p)
            return p, g, x, y
        else:
            j += 1

    print("Could not find appropriate g.")


def elgamal_keygen_recovery(p, g, y):
    # print("elgamal keygen recovery")
    attacker_dict = read_file("files/attacker.json")
    D, N, K = attacker_dict["rsa_d"], attacker_dict["rsa_n"], attacker_dict["K"]
    B1, B2 = 16, 512
    j = 0

    while j < B2:
        x2 = R2_inverse(g, K+j)
        x1 = pow(x2, D, N)
        i = 0

        while i < B1:
            x = R1_inverse(x1, K+i)
            if pow(g, x, p) == y % p:
                return x
            else:
                i += 1
        j += 1
    # print("SETUP not used")
    return None


def elgamal_signature_setup(m, x, p, g):
    # print("ElGamal signature setup")
    device_dict = read_file("files/device.json")
    k = device_dict["k"]
    Y = device_dict["y"]

    # first time
    if k is None:
        k = random.StrongRandom().randint(1, p - 2)
        while number.GCD(k, p-1) != 1:
            k = random.StrongRandom().randint(1, p - 2)

        device_dict["k"] = k
        save_file(device_dict, "files/device.json")

        r = pow(g, k, p)
        s = pow(k, -1, p-1) * (m - x*r) % (p - 1)
        return m, r, s

    else:  # second time
        c = pow(Y, k, p)
        if number.GCD(c, p-1) == 1 and number.GCD(pow(g, pow(c, -1, p-1), p), p-1) == 1:
            k = pow(c, -1, p-1)
            # print("used SETUP!")
        else:
            k = random.StrongRandom().randint(1, p-2)
            while number.GCD(k, p-1) != 1:
                k = random.StrongRandom().randint(1, p-2)

        device_dict["k"] = k
        save_file(device_dict, "files/device.json")

        r = pow(g, k, p)
        s = pow(k, -1, p-1) * (m - x*r) % (p - 1)
        return m, r, s


def elgamal_signature_recovery(r, m1, r1, s1):
    # print("ElGamal signature recovery")
    attacker_dict = read_file("files/attacker.json")
    p = attacker_dict["p"]
    X = attacker_dict["elgamal"][1]

    if number.GCD(r1, p-1) != 1:
        # print("SETUP not used")
        return None
    else:
        c = pow(r, X, p)
        try:
            x = pow(r1, -1, p-1) * (m1 - s1 * pow(c, -1, p-1)) % (p-1)
            return x
        except:
            return None


"""

def discrete_log_kleptogram(p, g):
    device_dict = read_file("device.json")
    c1 = device_dict["c1"]
    W = device_dict["W"]
    attacker_y = device_dict["y"]
    a, b = device_dict["a"], device_dict["b"]

    # first time
    if c1 is None:
        c1 = random.StrongRandom().randint(1, p-1)
        device_dict["c1"] = c1
        save_file(device_dict, "device.json")
        return pow(g, c1, p)

    else:  # second time
        t = random.StrongRandom().randint(0, 1)
        z = pow(g, c1 - W*t, p) * pow(attacker_y, -a*c1 - b, p) % p
        phi = p - 1
        print("phi:", len(str(phi)), phi)
        c2 = H(z)

        device_dict["c2"] = c2
        save_file(device_dict, "device.json")

        if c2 < phi:
            print("c2", len(str(c2)), c2)
            return p, g, c2, pow(g, c2, p)
        else:
            print("H(z) is not smaller than phi(p).")
            
            
def discrete_log_kleptogram(p, g):
    device_dict = read_file("device.json")
    c1 = device_dict["c1"]
    W = device_dict["W"]
    attacker_y = device_dict["y"]
    a, b = device_dict["a"], device_dict["b"]

    # first time
    if c1 is None:
        c1 = random.StrongRandom().randint(1, p-1)
        device_dict["c1"] = c1
        save_file(device_dict, "device.json")
        return pow(g, c1, p)

    else:  # second time
        t = random.StrongRandom().randint(0, 1)
        z = pow(g, c1 - W*t, p) * pow(attacker_y, -a*c1 - b, p) % p
        phi = p - 1
        print("phi:", len(str(phi)), phi)
        c2 = H(z)

        device_dict["c2"] = c2
        save_file(device_dict, "device.json")

        if c2 < phi:
            print("c2", len(str(c2)), c2)
            return p, g, c2, pow(g, c2, p)
        else:
            print("H(z) is not smaller than phi(p).")
            
            
def discrete_log_kleptogram_recovery(m1, m2, p, g):
    attacker_dict = read_file("attacker.json")
    W = attacker_dict["W"]
    attacker_elgamal = attacker_dict["elgamal"]
    a, b = attacker_dict["a"], attacker_dict["b"]

    X = attacker_elgamal.x
    r = pow(m1, a, p) * pow(g, b, p) % p
    z1 = m1 * pow(r, -X, p) % p
    if m2 == pow(g, H(z1)) % p:
        c2 = H(z1)
    z2 = z1 * pow(g, -W, p) % p
    if m2 == pow(g, H(z2)) % p:
        c2 = H(z2)

    # from c2, we can get A's private key
"""