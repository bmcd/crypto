import unittest

import conv
import xortools
import aestools
import encoding
import random
import frequency
import mt
import random
import time


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

    def test_challenge_19(self):
        """ Challenge 19: Break fixed-nonce CTR """

        key = aestools.random_key(16)
        nonce = bytes(8)
        input_file = open('files/19.txt', 'r')
        lines = [conv.base_64_to_bytes(line.rstrip()) for line in input_file]
        input_file.close()
        encrypted_lines = [aestools.do_ctr(line, key, nonce) for line in lines]

        index = 0
        probable_bytes = bytearray()
        while(True):
            rotated = "".join([chr(line[index]) if index < len(line) else '' for line in encrypted_lines])
            b, all, score = xortools.solve_xor_block(bytes(rotated, 'utf-8'))
            probable_bytes.append(b)
            index += 1
            if len(rotated) == 0: break

        for line in encrypted_lines:
            close = xortools.xor_bytes(line, bytes(probable_bytes[0 : len(line)]))
            readable = " ".join([chr(b) if b in range(32, 127) else 'X' for b in close])
            #print(readable)

        # no need to automate everything, from here i would manually adjust bytes

    def test_challenge_20(self):
        """ Challenge 20: Break fixed-nonce CTR Statistically """

        key = aestools.random_key(16)
        nonce = bytes(8)
        input_file = open('files/20.txt', 'r')
        lines = [conv.base_64_to_bytes(line.rstrip()) for line in input_file]
        input_file.close()
        encrypted_lines = [aestools.do_ctr(line, key, nonce) for line in lines]
        min_length = min([len(line) for line in encrypted_lines])
        concatted = b''.join([line[0:min_length] for line in encrypted_lines])
        test = xortools.breakxor(concatted, min_length)
        #print(test)

        # this is even closer than the last one, still would require tweaking a couple bytes

    def test_challenge_22(self):
        """ Challenge 22: MT seed finding, uncomment to run """

        #start_time = int(round(time.time() * 1000))
        #first_rand = mt.wait_seed_wait_rand()
        #end_time = int(round(time.time() * 1000))
        #for seed in range(start_time, end_time):
        #    generator = mt.MT19937(seed)
        #    if(generator.extract_number() == first_rand):
        #        print("Found seed: ")
        #        print(seed)
        #        break
        




if __name__ == '__main__':
    unittest.main()
