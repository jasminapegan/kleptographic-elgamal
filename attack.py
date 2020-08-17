import elgamal
import setups
from storage import init_attacker, init_device, read_file


# encryption scheme
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
print("\tA's keys:", key_a_private, key_a_public)
key_b_public, key_b_private = elgamal.keygen(p, g)
print("\tB's keys:", key_b_private, key_b_public)

# A sends to B pair (r, s)
m = 987654321
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


# signature scheme
print("\nSIGNATURE SCHEME")

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
m1 = 123456789
m1, r1, s1 = setups.elgamal_signature_setup(m1, key_a_private, p, g)
print("\tmessage, r, sig:", m1, r1, s1)
m2 = 987654321
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
"""

count = 0
err = 0
for i in range(100):
    # victim (A) initializes ElGamal
    p, g = elgamal.init_elgamal(2048)

    # attacker needs the same prime p as victim!
    init_attacker(p, g)
    attacker_dict = read_file("files/attacker.json")
    init_device(attacker_dict)

    # keygen
    key_a_public, key_a_private = elgamal.keygen(p, g)
    key_b_public, key_b_private = elgamal.keygen(p, g)

    # A signs two messages and sends them
    m1 = 123456789
    m1, r1, s1 = setups.elgamal_signature_setup(m1, key_a_private, p, g)
    m2 = 987654321
    m2, r2, s2 = setups.elgamal_signature_setup(m2, key_a_private, p, g)

    # attacker can recover A's private key
    try:
        x = setups.elgamal_signature_recovery(r1, m2, r2, s2)
        if x == key_a_private:
            count += 1
    except:
        print("Exception occurred.")
        err += 1

print("result:", count/(100 - err), "%")
print("all:", count / 100, "%")
"""
