from cryptography.hazmat.primitives import hashes

def hash_message(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message.encode())
    return digest.finalize()

message = "This is a message to hash."
hash_value = hash_message(message)
print(f"Hash value: {hash_value.hex()}")
