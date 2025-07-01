import os
import unittest
from Main import encrypt_message, decrypt_message


class MyTestCase(unittest.TestCase):
        """
        The 3 first tests from : AES WITH IPsec part 6: Test Vectors
        """
        def test_01_vector_1_single_block(self):
            print("\nRunning Test 1: Plaintext String : 'Single block msg'")
            # Define Test Data
            key_hex = "AE 68 52 F8 12 10 67 CC 4B F7 A5 76 55 77 F3 9E"
            nonce_hex = "00 00 00 30"
            iv_hex = "00 00 00 00 00 00 00 00"
            plaintext_hex = "53 69 6E 67 6C 65 20 62 6C 6F 63 6B 20 6D 73 67"
            expected_ciphertext_hex = "E4 09 5D 4F B7 A7 B3 79 2D 61 75 A3 26 13 11 B8"

            # Convert from Hex to Bytes
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex)
            iv = bytes.fromhex(iv_hex)
            plaintext = bytes.fromhex(plaintext_hex)
            expected_ciphertext = bytes.fromhex(expected_ciphertext_hex)

            # Encrypt
            ciphertext = encrypt_message(key, nonce, iv, plaintext)

            # Assert Encryption
            self.assertEqual(ciphertext, expected_ciphertext, "Ciphertext mismatch for TestVector 1")

            # Decrypt and Assert
            decrypted_text = decrypt_message(key, nonce, iv, ciphertext)
            self.assertEqual(decrypted_text, plaintext, "Decryption failed for TestVector 1")

        def test_02_vector_2_multiple_full_blocks(self):
            """
            Tests AES-CTR with two full blocks (32 bytes) of plaintext.
            """
            print("\nRunning Test 2: Multiple Full Blocks")
            # Define Test Data
            key_hex = "7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63"
            nonce_hex = "00 6C B6 DB"
            iv_hex = "C0 54 3B 59 DA 48 D9 0B"
            plaintext_hex = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"
            expected_ciphertext_hex = "51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88 EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28"

            # Convert from Hex to Bytes
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex)
            iv = bytes.fromhex(iv_hex)
            plaintext = bytes.fromhex(plaintext_hex)
            expected_ciphertext = bytes.fromhex(expected_ciphertext_hex)

            # Encrypt
            ciphertext = encrypt_message(key, nonce, iv, plaintext)

            # Assert Encryption
            self.assertEqual(ciphertext, expected_ciphertext, "Ciphertext mismatch for TestVector 2")

            # Decrypt and Assert
            decrypted_text = decrypt_message(key, nonce, iv, ciphertext)
            self.assertEqual(decrypted_text, plaintext, "Decryption failed for TestVector 2")

        def test_03_vector_3_partial_last_block(self):
            """
            Tests AES-CTR with multiple blocks, where the last block is partial. (overall 36 bytes)
            """
            print("\nRunning TestVector 3: Partial Last Block")

            # Define Test Data
            key_hex = "76 91 BE 03 5E 50 20 A8 AC 6E 61 85 29 F9 A0 DC"
            nonce_hex = "00 E0 01 7B"
            iv_hex = "27 77 7F 3F 4A 17 86 F0"
            plaintext_hex = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23"
            expected_ciphertext_hex = "C1 CF 48 A8 9F 2F FD D9 CF 46 52 E9 EF DB 72 D7 45 40 A4 2B DE 6D 78 36 D5 9A 5C EA AE F3 10 53 25 B2 07 2F"

            # Convert from Hex to Bytes
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex)
            iv = bytes.fromhex(iv_hex)
            plaintext = bytes.fromhex(plaintext_hex)
            expected_ciphertext = bytes.fromhex(expected_ciphertext_hex)

            # Encrypt
            ciphertext = encrypt_message(key, nonce, iv, plaintext)

            # Assert Encryption
            self.assertEqual(ciphertext, expected_ciphertext, "Ciphertext mismatch for TestVector 3")

            # Decrypt and Assert
            decrypted_text = decrypt_message(key, nonce, iv, ciphertext)

            self.assertEqual(decrypted_text, plaintext, "Decryption failed for TestVector 3")

        def test_04_empty_plaintext(self):
            print("\nRunning Test 4: Empty Plaintext")
            # Define Test Data
            key_hex = "AE6852F8121067CC4BF7A5765577F39E"
            nonce_hex = "00000030"
            iv_hex = "0000000000000000"
            plaintext = b""
            expected_ciphertext = b""

            # Convert from Hex to Bytes
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex)
            iv = bytes.fromhex(iv_hex)

            # Encrypt
            ciphertext = encrypt_message(key, nonce, iv, plaintext)
            # Assert Encryption
            self.assertEqual(ciphertext, expected_ciphertext, "Ciphertext mismatch for empty plaintext")
            # Decrypt and Assert
            decrypted_text = decrypt_message(key, nonce, iv, ciphertext)
            self.assertEqual(decrypted_text, plaintext, "Decryption failed for empty plaintext")

        def test_05_invalid_key_length(self):
            print("\nRunning Test 5: Invalid Key Length")
            # Define Test Data
            key_hex = "AE6852F8121067CC4BF7A5765577"  # 112 bits instead of 128
            nonce_hex = "00000030"
            iv_hex = "0000000000000000"
            plaintext_hex = "53696E676C6520626C6F636B206D7367"
            # Convert from Hex to Bytes
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex)
            iv = bytes.fromhex(iv_hex)
            plaintext = bytes.fromhex(plaintext_hex)

            with self.assertRaises(ValueError, msg="Expected ValueError for invalid key length"):
                encrypt_message(key, nonce, iv, plaintext)

        def test_06_invalid_iv_length(self):
            print("\nRunning Test 6: Invalid IV Length")
            # Define Test Data
            key_hex = "AE6852F8121067CC4BF7A5765577F39E"
            nonce_hex = "00000030"
            iv_hex = "00000000000000"  # 48 bits instead of 64
            plaintext_hex = "53696E676C6520626C6F636B206D7367"
            # Convert from Hex to Bytes
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex)
            iv = bytes.fromhex(iv_hex)
            plaintext = bytes.fromhex(plaintext_hex)

            with self.assertRaises(ValueError, msg="Expected ValueError for invalid IV length"):
                encrypt_message(key, nonce, iv, plaintext)

        def test_07_reused_iv(self):
            """
            Test to demonstrate the danger of reusing the same IV and Nonce with the same key in AES-CTR mode.
            When the same keystream is used to encrypt two different plaintexts, XORing the ciphertexts
            reveals the XOR of the plaintexts, which can leak sensitive information.
            """
            print("\nRunning Test 7: Reused counter_block")
            # Define Test Data
            key_hex = "AE6852F8121067CC4BF7A5765577F39E"
            nonce_hex = "00000030"
            iv_hex = "0000000000000000"
            plaintext1_hex = "53696E676C6520626C6F636B206D7367"
            plaintext2_hex = "48656C6C6F20776F726C64206D736720"  # Different plaintext
            # Convert from Hex to Bytes
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex)
            iv = bytes.fromhex(iv_hex)
            plaintext1 = bytes.fromhex(plaintext1_hex)
            plaintext2 = bytes.fromhex(plaintext2_hex)
            # Encrypt
            ciphertext1 = encrypt_message(key, nonce, iv, plaintext1)
            ciphertext2 = encrypt_message(key, nonce, iv, plaintext2)

            # XOR the ciphertexts to check for key stream reuse
            xor_result = bytes(a ^ b for a, b in zip(ciphertext1, ciphertext2))
            expected_xor = bytes(a ^ b for a, b in zip(plaintext1, plaintext2))
            self.assertEqual(xor_result, expected_xor, "Reused counter_block did not produce expected XOR result")

        def test_08_long_plaintext(self):
            print("\nRunning Test 8: Long Plaintext (1024 bytes)")
            # Define Test Data
            key_hex = "AE6852F8121067CC4BF7A5765577F39E"
            nonce_hex = "00000030"
            iv_hex = "0000000000000000"
            plaintext = os.urandom(1024)  # 1024 bytes of random data
            # Convert from Hex to Bytes
            key = bytes.fromhex(key_hex)
            nonce = bytes.fromhex(nonce_hex)
            iv = bytes.fromhex(iv_hex)
            # Encrypt
            ciphertext = encrypt_message(key, nonce, iv, plaintext)
            # Decrypt and Assert
            decrypted_text = decrypt_message(key, nonce, iv, ciphertext)
            self.assertEqual(decrypted_text, plaintext, "Decryption failed for long plaintext")

        def test_09_different_iv_produces_different_ciphertext(self):
            """
            Encrypt the same plaintext with the same key and different IVs.
            Verify that ciphertexts are different due to IV affecting the keystream.
            """
            print("\nRunning Test 9: Different IV Produces Different Ciphertext")
            # Define Test Data
            key = os.urandom(16)
            nonce = os.urandom(4)
            plaintext = b"Different IVs produce different ciphertexts."
            iv1 = os.urandom(8)
            iv2 = os.urandom(8)

            # Encrypt
            ciphertext1 = encrypt_message(key, nonce, iv1, plaintext)
            ciphertext2 = encrypt_message(key, nonce, iv2, plaintext)

            self.assertNotEqual(ciphertext1, ciphertext2)

        def test_10_same_encrypt_message_twice(self):
            """
            Encrypt the same plaintext with the same key and IV and nonce.
            Verify that encrypt messages are same.
            """
            print("\nRunning Test 10: Same Encrypt Message Twice")
            # Define Test Data
            key = os.urandom(16)
            nonce = os.urandom(4)
            iv = os.urandom(8)
            plaintext = b"The same encrypt message twice."

            # Encrypt
            ciphertext1 = encrypt_message(key, nonce, iv, plaintext)
            ciphertext2 = encrypt_message(key, nonce, iv, plaintext)

            self.assertEqual(ciphertext1, ciphertext2)

        def test_11_encrypt_same_plaintext_different_key(self):
            """
            Encrypt the same plaintext with the different key.
            Verify that ciphertexts are different.
            """
            print("\nRunning Test 11: Encrypt Same Plaintext Different Keys")
            # Define Test Data
            key = os.urandom(16)
            nonce = os.urandom(4)
            iv = os.urandom(8)
            plaintext = b"Different encrypt message."

            # Encrypt
            ciphertext1 = encrypt_message(key, nonce, iv, plaintext)
            key = os.urandom(16)
            ciphertext2 = encrypt_message(key, nonce, iv, plaintext)

            self.assertNotEqual(ciphertext1, ciphertext2)

if __name__ == "__main__":
    unittest.main()