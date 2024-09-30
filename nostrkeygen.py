import coincurve
import binascii
from bech32 import bech32_encode, bech32_decode, convertbits

# Helper functions for Bech32 encoding/decoding
def to_bech32(hrp, data):
    """Convert data to bech32 encoding with the specified human-readable part (hrp)."""
    five_bit_data = convertbits(data, 8, 5)
    return bech32_encode(hrp, five_bit_data)

def from_bech32(bech32_str):
    """Decode a bech32 string back to its original bytes."""
    hrp, five_bit_data = bech32_decode(bech32_str)
    return convertbits(five_bit_data, 5, 8, False)

# Generate a secret key (private key)
sk = coincurve.PrivateKey()

# Convert the secret key to a Uint8Array-like format (bytes in Python)
secret_key_bytes = sk.secret

# Derive the public key from the secret key
pk = sk.public_key

# Convert the public key to a hex string
public_key_hex = pk.format(compressed=True).hex()

# Convert the secret key bytes to a hex string
sk_hex = binascii.hexlify(secret_key_bytes).decode('utf-8')

# Convert the secret key to nsec (Bech32 encoding)
nsec = to_bech32('nsec', secret_key_bytes)

# Convert the public key to npub (Bech32 encoding)
npub = to_bech32('npub', pk.format(compressed=True))

# Convert the nsec back to bytes
back_to_bytes = bytes(from_bech32(nsec))

# Output the keys and conversions
print("Secret Key (bytes):", secret_key_bytes)
print("Secret Key (hex):", sk_hex)
print("Public Key (hex):", public_key_hex)
print("Nsec (Bech32):", nsec)
print("Npub (Bech32):", npub)
print("Back to bytes (from nsec):", back_to_bytes)
print("Is conversion back to bytes correct:", back_to_bytes == secret_key_bytes)
