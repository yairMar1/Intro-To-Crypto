import binascii
import os

from Crypto.Cipher import AES
from Crypto.Util import Counter

def hex_to_bytes(hex_str):
    # Convert a hex string (e.g., 'AE 68 52 F8') to bytes.
    hex_str = hex_str.replace(" ", "")
    return binascii.unhexlify(hex_str)


def bytes_to_hex_string(b):
    # Convert bytes to a space-separated hex string (e.g., 'AE 68 52 F8').
    return " ".join(f"{byte:02X}" for byte in b)


def generate_counter_block(nonce, iv, counter):
    # Generate a 16-byte Counter Block: Nonce (4 bytes) + IV (8 bytes) + Counter (4 bytes).
    counter_bytes = counter.to_bytes(4, byteorder="big")
    return nonce + iv + counter_bytes


def encrypt_message(key, nonce, iv, plaintext, counter_start=1):
    prefix = nonce + iv
    ctr_object = Counter.new(32, prefix=prefix, initial_value=counter_start)

    cipher = AES.new(key, AES.MODE_CTR, counter=ctr_object)
    ciphertext = cipher.encrypt(plaintext)

    # The following part is only for demonstration purposes
    block_size = 16
    key_streams = [] # K_i
    counter_blocks = [] # CTR_i
    num_blocks = (len(plaintext) + block_size - 1) // block_size

    for i in range(num_blocks):
        counter_block_val = generate_counter_block(nonce, iv, counter_start + i)
        counter_blocks.append(counter_block_val)

        # Recreate cipher for each block to get the specific keystream
        ctr_block_obj = Counter.new(32, prefix=prefix, initial_value=counter_start + i)
        cipher_block = AES.new(key, AES.MODE_CTR, counter=ctr_block_obj)

        key_stream = cipher_block.encrypt(b"\x00" * block_size)
        if i == num_blocks - 1 and len(plaintext) % block_size != 0:
            key_stream = key_stream[:len(plaintext) % block_size]
        key_streams.append(key_stream)

    return ciphertext, key_streams, counter_blocks


def decrypt_message(key, nonce, iv, ciphertext, counter_start=1):
    prefix = nonce + iv
    ctr_object = Counter.new(32, prefix=prefix, initial_value=counter_start)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr_object)
    return cipher.decrypt(ciphertext)


def main():
    print("--- Demonstration of AES 128-CTR Encryption with Random Values ---")

    random_key = os.urandom(16)  # 128-bit key (16 bytes)
    random_nonce = os.urandom(4)  # 32-bit nonce (4 bytes)
    random_iv = os.urandom(8)  # 64-bit IV (8 bytes)

    # Here we define a plaintext message to encrypt
    plaintext_str = "This is a secret message for the demo!"
    plaintext_bytes = plaintext_str.encode('utf-8')

    ciphertext, key_streams, counter_blocks = encrypt_message(
        random_key,
        random_nonce,
        random_iv,
        plaintext_bytes
    )

    decrypted_bytes = decrypt_message(
        random_key,
        random_nonce,
        random_iv,
        ciphertext
    )

    print(f"Encrypting {len(plaintext_bytes)} octets using AES-CTR with 128-bit key\n")
    print(f"Random AES Key   : {bytes_to_hex_string(random_key)}")
    print(f"Random Nonce     : {bytes_to_hex_string(random_nonce)}")
    print(f"Random IV        : {bytes_to_hex_string(random_iv)}\n")
    print(f"Original Plaintext: '{plaintext_str}'")
    print(f"Plaintext (Hex)   : {bytes_to_hex_string(plaintext_bytes)}\n")

    for i in range(len(counter_blocks)):
        print(f"Counter Block ({i + 1}): {bytes_to_hex_string(counter_blocks[i])}")
        print(f"Key Stream ({i + 1})   : {bytes_to_hex_string(key_streams[i])}")

    print(f"\nGenerated Ciphertext: {bytes_to_hex_string(ciphertext)}\n")
    print(f"Decrypted Text (Hex): {bytes_to_hex_string(decrypted_bytes)}")
    print(f"Decrypted Text      : '{decrypted_bytes.decode('utf-8', errors='ignore')}'\n")

    if plaintext_bytes == decrypted_bytes:
        print("SUCCESS: Decrypted text matches the original plaintext.")
    else:
        print("FAILURE: Decrypted text does not match the original plaintext.")


if __name__ == "__main__":
    main()