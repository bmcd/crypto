import unittest

import conv
import xortools
import aestools


class Challenges(unittest.TestCase):
    

    def test_challenge_1(self):
        """ Challenge 1: Convert Hex String to Base64 String """

        input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        expected_out = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

        self.assertEqual(conv.hex_to_base_64(input), expected_out)

    def test_challenge_2(self):
        """ Challenge 2: XOR two strings """

        input_one = '1c0111001f010100061a024b53535009181c'
        input_two = '686974207468652062756c6c277320657965'
        expected_out = '746865206b696420646f6e277420706c6179'

        bytes_one = conv.hex_to_bytes(input_one)
        bytes_two = conv.hex_to_bytes(input_two)
        expected_bytes_out = conv.hex_to_bytes(expected_out)

        self.assertEqual(xortools.xor_bytes(bytes_one, bytes_two), expected_bytes_out)

    def test_challenge_3(self):
        """ Challenge 3: Find xor cipher byte """

        input = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        input_bytes = conv.hex_to_bytes(input)

        b, output, score = xortools.solve_xor_block(input_bytes)
        self.assertEqual(b, 88)
        self.assertEqual(output, b"Cooking MC's like a pound of bacon")

    def test_challenge_4(self):
        """ Challenge 4: Find XORed string in file (Slow, uncomment to run) """

#        input_file = open('files/4.txt', 'r')
#        encrypted, decrypted = xortools.find_xored_bytes(input_file)
#        input_file.close()
#        self.assertEqual(conv.bytes_to_hex(encrypted), '7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f')

    def test_challenge_5(self):
        """ Challenge 5: Implement repeating key XOR """

        input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        input_bytes = input.encode("utf-8")
        key = "ICE"
        key_bytes = key.encode("utf-8")

        expected_output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        hex_output = conv.bytes_to_hex(xortools.xor_repeating(input_bytes, key_bytes))
        self.assertEqual(hex_output, expected_output)

    def test_challenge_6(self):
        """ Challenge 6: Break repeating key XOR """

        file = open('files/6.txt', 'r')
        input = file.read()
        file.close()
        input_bytes = conv.base_64_to_bytes(input)
        key, output = xortools.breakxor(input_bytes)
        self.assertEqual(key, b'Terminator X: Bring the noise')

    def test_challenge_7(self):
        """ Challenge 7: Decrypt AES """

        in_file = open("files/7.txt", "r")
        input = conv.base_64_to_bytes(in_file.read())
        in_file.close()

        output_bytes = aestools.decrypt_ecb(input, "YELLOW SUBMARINE")
        output = output_bytes.decode("utf-8")

        expected_file = open('files/7_expected.txt', 'r')
        self.assertEqual(output, expected_file.read())
        expected_file.close()

    def test_challenge_8(self):
        """ Challenge 8: Detect AES ECB """

        file = open('files/8.txt', 'r')
        self.assertEqual(aestools.find_aes(file), 'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a')
        file.close()

    def test_challenge_9(self):
        """ Challenge 9: Padding """

        input = b'YELLOW SUBMARINE'
        desired_length = 20

        self.assertEqual(aestools.padded(input, desired_length), b'YELLOW SUBMARINE\x04\x04\x04\x04')

    def test_challenge_10(self):
        """ Challenge 10: Decrypt CBC """

        file = open('files/10.txt', 'r')
        input = conv.base_64_to_bytes(file.read().rstrip())
        file.close()

        expected_file = open('files/10_expected.txt', 'r')
        expected_bytes = expected_file.read().encode("utf-8")
        expected_file.close()

        decrypted = aestools.decrypt_cbc(input, bytes("YELLOW SUBMARINE", "ascii"), b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

        self.assertEqual(decrypted, expected_bytes)

    def test_challenge_11(self):
        """ Challenge 11: Detect ECB or CBC """
        
        # took me a while to realize that I could know the input bytes :)
        for x in range(16):
            (test, mode) = aestools.encryption_oracle(bytes(128))
            self.assertEqual(aestools.detect_mode(test), mode)

    def test_challenge_12(self):
        """ Challenge 12: Decrypt ECB 1 byte at a time """

        result = aestools.break_ECB_1_byte(aestools.black_box)
        self.assertEqual(result, conv.base_64_to_bytes(aestools.TEXT))

    def test_challenge_13(self):
        """ Challenge 13: ECB cut and paste """

if __name__ == '__main__':
    unittest.main()
