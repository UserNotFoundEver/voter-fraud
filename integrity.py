import hashlib

def check_integrity(file_path, expected_hash):
    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest() == expected_hash

# Example usage for checking INTEGRITY of VOTES.
if not check_integrity("voting_client.exe", "expected_hash_value"):
    print("Client integrity check failed. Possible tampering detected.")
