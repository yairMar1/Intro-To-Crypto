import unittest
from Main import encrypt_message, decrypt_message, hex_to_bytes


class MyTestCase(unittest.TestCase):

    def test_vector_1_single_block(self):
        print("\nRunning TestVector 1 (Single Block)...")

        # 1. Define Test Data
        key_hex = "AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E"
        nonce_hex = "00 00 00 30"
        iv_hex = "00 00 00 00 00 00 00 00"
        plaintext_hex = "53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67"
        expected_ciphertext_hex = "E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8"

        # 2. Convert from Hex to Bytes
        key = hex_to_bytes(key_hex)
        nonce = hex_to_bytes(nonce_hex)
        iv = hex_to_bytes(iv_hex)
        plaintext = hex_to_bytes(plaintext_hex)
        expected_ciphertext = hex_to_bytes(expected_ciphertext_hex)

        # 3. Encrypt
        # We ignore the demonstration return values (key_streams, counter_blocks)
        ciphertext, _, _ = encrypt_message(key, nonce, iv, plaintext)

        # 4. Assert Encryption
        self.assertEqual(ciphertext, expected_ciphertext, "Ciphertext mismatch for TestVector 1")

        # 5. Decrypt and Assert
        decrypted = decrypt_message(key, nonce, iv, ciphertext)
        self.assertEqual(decrypted, plaintext, "Decryption failed for TestVector 1")

    def test_vector_2_multiple_full_blocks(self):
        print("Running TestVector 2 (Multiple Full Blocks)...")

        # 1. Define Test Data
        key_hex = "7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63"
        nonce_hex = "00 6C B6 DB"
        iv_hex = "C0 54 3B 59 DA 48 D9 0B"
        plaintext_hex = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
        expected_ciphertext_hex = "51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88 EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28"

        # 2. Convert from Hex to Bytes
        key = hex_to_bytes(key_hex)
        nonce = hex_to_bytes(nonce_hex)
        iv = hex_to_bytes(iv_hex)
        plaintext = hex_to_bytes(plaintext_hex)
        expected_ciphertext = hex_to_bytes(expected_ciphertext_hex)

        # 3. Encrypt
        ciphertext, _, _ = encrypt_message(key, nonce, iv, plaintext)

        # 4. Assert Encryption
        self.assertEqual(ciphertext, expected_ciphertext, "Ciphertext mismatch for TestVector 2")

        # 5. Decrypt and Assert
        decrypted = decrypt_message(key, nonce, iv, ciphertext)
        self.assertEqual(decrypted, plaintext, "Decryption failed for TestVector 2")

    def test_vector_3_partial_last_block(self):
        print("Running TestVector 3 (Partial Last Block)...")

        # 1. Define Test Data
        key_hex = "76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC"
        nonce_hex = "00 E0 01 7B"
        iv_hex = "27 77 7F 3F 4A 17 86 F0"
        plaintext_hex = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23"
        expected_ciphertext_hex = "C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7 45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53 25 B2 07 2F"

        # 2. Convert from Hex to Bytes
        key = hex_to_bytes(key_hex)
        nonce = hex_to_bytes(nonce_hex)
        iv = hex_to_bytes(iv_hex)
        plaintext = hex_to_bytes(plaintext_hex)
        expected_ciphertext = hex_to_bytes(expected_ciphertext_hex)

        # 3. Encrypt
        ciphertext, _, _ = encrypt_message(key, nonce, iv, plaintext)

        # 4. Assert Encryption
        self.assertEqual(ciphertext, expected_ciphertext, "Ciphertext mismatch for TestVector 3")

        # 5. Decrypt and Assert
        decrypted = decrypt_message(key, nonce, iv, ciphertext)
        self.assertEqual(decrypted, plaintext, "Decryption failed for TestVector 3")


if __name__ == "__main__":
    unittest.main()