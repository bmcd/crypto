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

    def test_get_prefix(self):
        aestools.PREFIX = aestools.random_key(6)
        function = aestools.get_black_box(True)
        blocksize, length = aestools.get_block_size_and_length(function)
        self.assertEqual(aestools.get_prefix_length(function, blocksize, length), 6)
        aestools.PREFIX = aestools.random_key(3)
        blocksize, length = aestools.get_block_size_and_length(function)
        self.assertEqual(aestools.get_prefix_length(function, blocksize, length), 3)
        aestools.PREFIX = aestools.random_key(23)
        blocksize, length = aestools.get_block_size_and_length(function)
        self.assertEqual(aestools.get_prefix_length(function, blocksize, length), 23)

    def test_quote_symbols(self):
        encrypted = aestools.cbc_black_box("test;admin=true;")
        self.assertFalse(aestools.has_admin_string(encrypted))

if __name__ == '__main__':
    unittest.main()
