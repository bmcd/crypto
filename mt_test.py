import unittest

import mt
import random


class Tests(unittest.TestCase):
    
    def test_randomness(self):
        """ Gives repeatable random numbers for same seed """

        rand = mt.MT19937(888)
        rand1a = rand.extract_number()
        rand2a = rand.extract_number()
        rand = mt.MT19937(888)
        rand1b = rand.extract_number()
        rand2b = rand.extract_number()
        rand = mt.MT19937(889)
        rand1c = rand.extract_number()
        rand2c = rand.extract_number()
        self.assertEqual(rand1a, rand1b)
        self.assertEqual(rand2a, rand2b)
        self.assertNotEqual(rand1a, rand1c)
        self.assertNotEqual(rand2a, rand2c)

    def test_untemper(self):
        """ Correctly applies the reverse of the tempering of the MT """

        untempered = random.randint(0, 10000000)
        tempered = untempered
        # Right shift by 11 bits
        tempered = tempered ^ tempered >> 11
        # Shift tempered left by 7 and take the bitwise and of 2636928640
        tempered = tempered ^ tempered << 7 & 2636928640
        # Shift tempered left by 15 and take the bitwise and of tempered and 4022730752
        tempered = tempered ^ tempered << 15 & 4022730752
        # Right shift by 18 bits
        tempered = tempered ^ tempered >> 18

        test = mt.untemper(tempered)
        self.assertEqual(untempered, test)

    def test_reverse_right(self):
        for i in range(30):
            input = random.randint(0, 0xFFFFFFFF)
            shift = random.randint(1, 32)
            shifted = input ^ input >> shift
            test = mt.reverse_right(shifted, shift)
            self.assertEqual(input, test)

    def test_reverse_left(self):
        for i in range(30):
            input = random.randint(0, 0xFFFFFFFF)
            shift = random.randint(1, 32)
            magic_number = random.randint(0, 0xFFFFFFFF)
            shifted = input ^ input << shift & magic_number
            test = mt.reverse_left(shifted, shift, magic_number)
            self.assertEqual(input, test)


if __name__ == '__main__':
    unittest.main()
