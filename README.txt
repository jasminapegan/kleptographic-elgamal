~~ Kleptography -- SETUP examples in ElGamal encryption scheme ~~

This project includes code that sets a simple example of how we can tweak cryptoprimitives so that they leak secret data.
And do this unnoticed. And no one else but us who SET it UP can recover the leaked data.

The code is based on algorithms found in Master's thesis "Kleptography – Overview and a new proof of concept"
by Ferdinand Blomqvist.

Requirements: Python 3.8
Dependencies: pycryptodome, factordb

~~ Where's What ~~

The code is divided into some logical units:
CLASSES
  - 'elgamal.py' includes basic ElGamal encryption/decryption and sign/verify function implementations
  - 'setups.py' includes the SETUPped examples of key generation and signing,
              plus the functions that attacker can use to recover secret data
  - 'storage.py' includes functions that deal with persistent data on infected device and the attacker's machine,
               each in its own separate json file
  - 'testing.py' includes functions that help with testing of correctness, time consumption and statistics of outputs,
               there are also the two examples from attack.py
  - 'helpers.py' contains some auxiliary functions: is_generator, stddev, R1 and R1_inverse, R2 and R2_inverse
SCRIPTS
  - 'attack.py' is a script that sets an example of each attack -- key generation SETUP and signing SETUP
  - 'main.py' is a script that runs a ton of example attacks and calculates statistics on the results
FILES

  - 'files/attacker.json' includes the attacker's knowledge -- his own keys, public data (p, g) and some additional data
  - 'files/device.json' includes variables that are stored on the infected device -- the owner's keys, attacker's public key
                and some additional data (previous calculated key etc.)
  - 'files/keys' includes generated private keys to help testing their randomness
  - 'files/signatures' includes generated signatures of random messages to help test signatures' randomness


2. 8. 2020
Jasmina Pegan
