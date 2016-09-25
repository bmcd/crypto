import unittest

import conv
import xortools
import aestools
import encoding
import random


class Challenges(unittest.TestCase):
    
    def test_challenge_17(self):
        """ Challenge 17: CBC padding oracle """

        cipher, iv = aestools.provide_cbc_ecrypted()
        self.assertTrue(aestools.is_valid_padding(cipher, iv))

        cracked = aestools.break_cbc_using_padding(aestools.is_valid_padding, cipher, iv)
        print(cracked)


if __name__ == '__main__':
    unittest.main()
