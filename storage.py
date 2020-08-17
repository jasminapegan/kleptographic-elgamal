from Crypto import Random
from Crypto.PublicKey import RSA
from elgamal import keygen
import json
from helpers import is_generator


def init_attacker(p, g, filename="attacker.json"):
    print("initalizing attacker...")
    attacker_dict = {}
    attacker_dict["p"] = p
    rsa_key = RSA.generate(2048, Random.new().read)
    attacker_dict["rsa_n"] = rsa_key.n
    attacker_dict["rsa_e"] = rsa_key.e
    attacker_dict["rsa_d"] = rsa_key.d
    attacker_dict["elgamal"] = keygen(p, g)
    K = p - 2
    while not is_generator(K, p):
        K -= 1
    attacker_dict["K"] = K
    save_file(attacker_dict, filename="files/" + filename)


def init_device(attacker_dict, filename="device.json"):
    print("initalizing SETUPped device...")
    device_dict = {}
    device_dict["rsa_n"] = attacker_dict["rsa_n"]
    device_dict["rsa_e"] = attacker_dict["rsa_e"]
    device_dict["y"] = attacker_dict["elgamal"][0]
    device_dict["c1"] = None
    device_dict["k"] = None
    device_dict["W"] = 7
    device_dict["a"] = 123456
    device_dict["b"] = 666666
    device_dict["K"] = attacker_dict["K"]
    save_file(device_dict, filename="files/" + filename)


def save_file(some_dict, filename):
    with open(filename, "w") as f:
        json.dump(some_dict, f)


def read_file(filename):
    with open(filename, "r") as f:
        some_dict = json.load(f)
    return some_dict
