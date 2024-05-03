import argon2
import os

username = "ankuia"
salt = os.urandom(16)  # Generate a random salt of length 16 bytes
hash_params = {
    "hash_len": 32,
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4,
    "type": argon2.low_level.Type.ID,
}

# Hash the username with the salt
hash_value = argon2.low_level.hash_secret_raw(username.encode(), salt, **hash_params)
print(hash_value.hex())
