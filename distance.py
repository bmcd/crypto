

class Distance(object):


    def __init__(self, keysize, distance):
        self.keysize = keysize
        self.distance = distance

    def __repr__(self):
        return "{}: {}".format(self.keysize, self.distance)

    def __lt__(self, other):
        return self.distance < other.distance
