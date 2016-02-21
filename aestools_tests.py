import unittest
import aestools


class AesToolsTestCase(unittest.TestCase):

    def test_padding(self):
        """ Adds specified padding to bytes """
        input = b'YELLOW SUBMARINE'
        desired_length = 20

        self.assertEqual(aestools.padded(input, desired_length), b'YELLOW SUBMARINE\x04\x04\x04\x04')

    def test_random_key(self):
        """ Creates random X byte aes key """
        key = aestools.random_key(16)
        keytwo = aestools.random_key(16)
        keythree = aestools.random_key(5)

        self.assertEqual(len(key), 16)
        self.assertEqual(len(keythree), 5)
        self.assertNotEqual(key, keytwo)

    def test_add_bytes(self):
        input = b'test'
        output = aestools.add_bytes_to_input(input)
        minlength = len(input) + 10
        maxlength = len(input) + 20

        self.assertNotEqual(input, output)
        self.assertTrue(minlength <= len(output) <= maxlength)

if __name__ == '__main__':
    unittest.main()
