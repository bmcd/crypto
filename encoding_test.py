import unittest

import encoding

class EncodingTestCase(unittest.TestCase):


    def test_parsing(self):
        """ Can parse a query string """

        input = 'foo=bar&baz=qux&zap=zazzle'
        output = encoding.parse(input)
        expected = { 'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle' }

        self.assertDictContainsSubset(expected, output)

    def test_encoding(self):

        input = { 'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle' }
        output = encoding.encode(input)
        expected = 'foo=bar&baz=qux&zap=zazzle'
        # TODO test this, dictionary messes with order

    def test_create_user(self):


        user = encoding.User("test@gmail.com")
        user2 = encoding.User("test2@gmail.com", 'admin')
        
        self.assertEqual(user.id, 1)
        self.assertEqual(user.role, 'user')

        self.assertEqual(user2.id, 2)
        self.assertEqual(user2.role, 'admin')

        print(encoding.profile_for('test@gmail.com'))

if(__name__ == '__main__'):
    unittest.main()
