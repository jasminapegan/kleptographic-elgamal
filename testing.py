import elgamal
import setups
from storage import init_attacker, init_device, read_file
from Crypto.Random import random
from time import time
from helpers import stddev


def encryption_scheme():
    print("ENCRYPTION SCHEME")
    p, g = elgamal.init_elgamal(2048)

    init_attacker(p, g)
    attacker_dict = read_file("files/attacker.json")
    init_device(attacker_dict)

    # victim (A) initializes ElGamal
    p, g = elgamal.init_elgamal(2048)

    # A and B calculate keys first time
    # A does so with SETUPped function (new generator g is chosen)
    p, g, key_a_private, key_a_public = setups.elgamal_keygen_setup(p=p)
    key_b_public, key_b_private = elgamal.keygen(p, g)

    # A sends to B pair (r, s)
    m = random.randint(0, 2**2048)
    r, s = elgamal.encrypt(m, key_b_public, p, g)
    print("Sent r, s:", r, s)

    # B reads the message
    m1 = elgamal.decrypt(r, s, key_b_private, p)
    print(m1)
    print("Message decrypted correctly:", m == m1)

    # attacker uses public info
    x = setups.elgamal_keygen_recovery(p, g, key_a_public)
    print("Recovered A's private key:", x)
    print("key is correct:", x == key_a_private)
    # success!


def signature_scheme():
    print("SIGNATURE SCHEME")
    # victim (A) initializes ElGamal
    p, g = elgamal.init_elgamal(2048)
    print("\tp, g:", p, g)

    # attacker needs the same prime p as victim!
    init_attacker(p, g)
    attacker_dict = read_file("files/attacker.json")
    init_device(attacker_dict)

    # keygen
    key_a_public, key_a_private = elgamal.keygen(p, g)
    print("\tA's keys:", key_a_private, key_a_public)
    key_b_public, key_b_private = elgamal.keygen(p, g)
    print("\tB's keys:", key_b_private, key_b_public)

    # A signs two messages and sends them
    m1 = random.randint(0, 2**2048)
    m1, r1, s1 = setups.elgamal_signature_setup(m1, key_a_private, p, g)
    print("\tmessage, r, sig:", m1, r1, s1)
    m2 = random.randint(0, 2**2048)
    m2, r2, s2 = setups.elgamal_signature_setup(m2, key_a_private, p, g)
    print("\tmessage, r, sig:", m2, r2, s2)

    # B can verify both signatures
    v1 = elgamal.verify(m1, r1, s1, key_a_public, p, g)
    print("Signature of first message is valid:", v1)
    v2 = elgamal.verify(m2, r2, s2, key_a_public, p, g)
    print("Signature of second message is valid:", v2)

    # attacker can recover A's private key
    x = setups.elgamal_signature_recovery(r1, m2, r2, s2)
    print("Attacker got x:", x)
    print("Key is correct:", x == key_a_private)


def init_encryption():
    p, g = elgamal.init_elgamal(2048)

    # A and B calculate keys first time
    # A does so with SETUPped function (new generator g is chosen)
    p, g, key_a_private, key_a_public = setups.elgamal_keygen_setup(p=p)
    key_b_public, key_b_private = elgamal.keygen(p, g)
    return p, g, key_a_private, key_a_public, key_b_public, key_b_private


def timing_keygen(n=1000):
    # calculating with fixed machine
    p, g = elgamal.init_elgamal(2048)

    times = []
    for i in range(n):
        # print(i)
        dt1 = time()
        elgamal.keygen_with_new_g(p, g)
        dt2 = time()
        times.append(dt2 - dt1)
    print("normal, n=%d. mean: %f, stddev: %f" % (n, sum(times) / n, stddev(times)))

    times = []
    for i in range(n):
        # print(i)
        dt1 = time()
        setups.elgamal_keygen_setup(p=p)
        dt2 = time()
        times.append(dt2 - dt1)
    avg = sum(times) / n
    print("setup, n=%d. mean: %f, stddev: %f" % (n, avg, stddev(times)))


def timing_signing(n=1000):
    # calculating with fixed signer data
    p, g = elgamal.init_elgamal(2048)
    p, g, x, _ = setups.elgamal_keygen_setup(p=p)
    messages = [random.randint(0, 2**2048) for _ in range(n)]

    times = []
    for i in range(n):
        dt1 = time()
        elgamal.sign(messages[i], x, p, g)
        dt2 = time()
        times.append(dt2 - dt1)
    print("normal, n=%d. mean: %f, stddev: %f" % (n, sum(times) / n, stddev(times)))

    times = []
    for i in range(n):
        dt1 = time()
        setups.elgamal_signature_setup(messages[i], x, p, g)
        dt2 = time()
        times.append(dt2 - dt1)
    print("setup, n=%d. mean: %f, stddev: %f" % (n, sum(times) / n, stddev(times)))


def compare_key_distributions(n=1000):
    p, g = elgamal.init_elgamal(2048)
    keys = []
    for i in range(n):
        keys.append(elgamal.keygen_with_new_g(p, g)[1])
    avg = sum(keys) / len(keys)
    print("normal, n=%d. mean: %f, stddev: %f" % (n, avg, stddev(keys)))

    keys = []
    for i in range(n):
        keys.append(setups.elgamal_keygen_setup(p)[2])
    avg = sum(keys) / len(keys)
    print("setup, n=%d. mean: %f, stddev: %f" % (n, avg, stddev(keys)))


def save_keys_to_file(n=1000, file='keys'):
    p, g = elgamal.init_elgamal(2048)
    with open("files/" + file, "wb") as f:
        for i in range(n):
            p, _, x, _ = setups.elgamal_keygen_setup(p=p)
            f.write(x.to_bytes(2048 // 8, 'little'))


def save_signatures_to_file(n=1000, file='signatures'):
    p, g = elgamal.init_elgamal(2048)
    p, g, x, _ = setups.elgamal_keygen_setup(p=p)
    with open("files/" + file, "wb") as f:
        for i in range(n):
            m = random.randint(0, 2**2048)
            m, r, s = setups.elgamal_signature_setup(m, x, p, g)
            f.write(s.to_bytes(2048 // 8, 'little'))


def do_keys_match_keygen(n=1000):
    # attacker inits
    p, g = elgamal.init_elgamal(2048)
    init_attacker(p, g)
    attacker_dict = read_file("files/attacker.json")

    # victim inits
    init_device(attacker_dict)
    p, g = elgamal.init_elgamal(2048)

    success = 0
    used_setup = n
    for i in range(n):
        p, g, key_a_private, key_a_public = setups.elgamal_keygen_setup(p=p)

        # attacker uses public info
        x = setups.elgamal_keygen_recovery(p, g, key_a_public)
        if x is None:
            used_setup -= 1
        elif x == key_a_private:
            success += 1

    return success / n, used_setup / n, success / used_setup


def do_keys_match_sign(n=1000):
    p, g = elgamal.init_elgamal(2048)

    # attacker needs the same prime p as victim!
    init_attacker(p, g)
    attacker_dict = read_file("files/attacker.json")
    init_device(attacker_dict)

    # keygen
    key_a_public, key_a_private = elgamal.keygen(p, g)

    # A signs two messages and sends them
    m1 = random.randint(0, 2**2048)
    m1, r1, s1 = setups.elgamal_signature_setup(m1, key_a_private, p, g)

    success = 0
    used_setup = n
    for i in range(n):
        m2 = random.randint(0, 2**2048)
        m2, r2, s2 = setups.elgamal_signature_setup(m2, key_a_private, p, g)

        # attacker tries to recover x
        x = setups.elgamal_signature_recovery(r1, m2, r2, s2)
        if x is None:
            used_setup -= 1
        elif x == key_a_private:
            success += 1

        m1, r1, s1 = m2, r2, s2

    return success / n, used_setup / n, success / used_setup
