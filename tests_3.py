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
        lines = [line.rstrip() for line in input_file]
        input_file.close()

        cipher, iv = aestools.provide_cbc_ecrypted(lines[random.randint(0, len(lines) - 1)])
        self.assertTrue(aestools.is_valid_padding(cipher))
        cipher[-2] = 9
        self.assertFalse(aestools.is_valid_padding(cipher))


if __name__ == '__main__':
    unittest.main()
