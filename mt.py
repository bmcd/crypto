import random
import time

def _int32(x):
    # Get the 32 least significant bits.
    return int(0xFFFFFFFF & x)

# TODO totally just stolen from wikipedia, I should understand this better
class MT19937:

    def __init__(self, seed):
        # Initialize the index to 0
        self.index = 624
        self.mt = [0] * 624
        self.mt[0] = seed  # Initialize the initial state to the seed
        for i in range(1, 624):
            self.mt[i] = _int32(
                1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    def extract_number(self):
        if self.index >= 624:
            self.twist()

        y = self.mt[self.index]

        # Right shift by 11 bits
        y = y ^ y >> 11
        # Shift y left by 7 and take the bitwise and of 2636928640
        y = y ^ y << 7 & 2636928640
        # Shift y left by 15 and take the bitwise and of y and 4022730752
        y = y ^ y << 15 & 4022730752
        # Right shift by 18 bits
        y = y ^ y >> 18

        self.index = self.index + 1

        return _int32(y)

    def twist(self):
        for i in range(624):
            # Get the most significant bit and add it to the less significant
            # bits of the next number
            y = _int32((self.mt[i] & 0x80000000) +
                       (self.mt[(i + 1) % 624] & 0x7fffffff))
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df
        self.index = 0

def wait_seed_wait_rand():
    random_seconds = random.randint(40, 1000)
    time.sleep(random_seconds)
    seed = int(round(time.time() * 1000))
    rand = MT19937(seed)
    random_seconds = random.randint(40, 1000)
    time.sleep(random_seconds)
    return rand.extract_number()

def untemper(value):
    value = reverse_right(value, 18)
    value = reverse_left(value, 15, 4022730752)
    value = reverse_left(value, 7, 2636928640)
    value = reverse_right(value, 11)
    return value

def reverse_right(value, shift):
    # we have the left shift bits already
    known = shift
    # if shift is less than 16, we need to run this multiple times
    while(known < 32):
        # intermediate is the input shifted by the bits
        intermediate = value >> shift
        # shift off already known bits on the left
        intermediate = _int32(intermediate << known) >> known
        # shift off unknown bits on the right past the known shifted
        if(32 > known + shift):
            unknown = 32 - (known + shift)
            intermediate = intermediate >> unknown << unknown
        value = value ^ intermediate
        known += shift

    return value

def reverse_left(value, shift, magic_number):
    known = 0
    while(known < 32):
        # we know that the bits on the right of the shifted value are 0
        shifted = _int32(value << shift)
        intermediate = shifted & magic_number
        # shift off already known bits on the right
        intermediate = intermediate >> known << known
        # shift off unknown bits on the left past the known shifted
        if(32 > known + shift):
            unknown = 32 - (known + shift)
            intermediate = _int32(intermediate << unknown) >> unknown
        value = value ^ intermediate
        known += shift

    return value

def print_bits(number):
    return format(number, '032b')

def clone_mt(original):
    # change internals later
    cloned = MT19937(1)
    array = [0] * 624
    for i in range(624):
        array[i] = untemper(original.extract_number())

    cloned.mt = array
    return cloned
