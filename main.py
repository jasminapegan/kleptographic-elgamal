from testing import *

"""
print("keygen: success / n, used_setup / n, success / used_setup")
print(do_keys_match_keygen(n=1000))

print("sign: success / n, used_setup / n, success / used_setup")
print(do_keys_match_sign(n=1000))

timing_keygen()
timing_signing()

save_keys_to_file()
save_signatures_to_file()

"""

timing_keygen(100000)
