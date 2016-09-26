import unittest

import mt


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

if __name__ == '__main__':
    unittest.main()
