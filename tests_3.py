import unittest

import conv
import xortools
import aestools
import encoding
import random


class Challenges(unittest.TestCase):
    
    def test_challenge_17(self):
        """ Challenge 17: CBC padding oracle """

        input_file = open('files/17.txt', 'r')
        lines = [conv.base_64_to_bytes(line.rstrip()) for line in input_file]
        input_file.close()
        cipher, iv = aestools.provide_cbc_ecrypted()
        self.assertTrue(aestools.is_valid_padding(cipher, iv))

        cracked = aestools.break_cbc_using_padding(aestools.is_valid_padding, cipher, iv)
        self.assertTrue(cracked in lines)


    def test_challenge_18(self):
        """ Challenge 18: CTR Encryption """

        test = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
        key = "YELLOW SUBMARINE"
        nonce = bytes(8)
        self.assertEqual(b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ", aestools.do_ctr(conv.base_64_to_bytes(test), key, nonce))
        
        roundtrip_input = conv.base_64_to_bytes(aestools.TEXT)
        roundtrip_encrypt = aestools.do_ctr(roundtrip_input, key, nonce)
        self.assertEqual(roundtrip_input, aestools.do_ctr(roundtrip_encrypt, key, nonce))


if __name__ == '__main__':
    unittest.main()
