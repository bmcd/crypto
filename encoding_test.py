import unittest
from collections import OrderedDict
import encoding

class EncodingTestCase(unittest.TestCase):


    def test_parsing(self):
        """ Can parse a query string """

        input = 'foo=bar&baz=qux&zap=zazzle'
        output = encoding.parse(input)
        expected = { 'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle' }

        self.assertDictContainsSubset(expected, output)

    def test_encoding(self):
        input = OrderedDict()
        input['foo'] = 'bar'
        input['baz'] = 'qux'
        input['zap'] = 'zazzle'
        output = encoding.encode(input)
        expected = 'foo=bar&baz=qux&zap=zazzle'
        self.assertEqual(expected, output)

    def test_create_user(self):
        user = encoding.create_or_get_user("test@gmail.com")
        user2 = encoding.create_or_get_user("test2@gmail.com")
        user1again = encoding.create_or_get_user("test@gmail.com")
        self.assertEqual(user.id, 1)
        self.assertEqual(user1again.id, 1)
        self.assertEqual(user2.id, 2)

    def test_disallow_symbols(self):
        input = "test@o=&.com"
        output = encoding.remove_symbols(input)
        self.assertEqual("test@o%3D%26.com", output)

    def test_is_admin(self):
        user = encoding.profile_for('user@example.com')
        admin = encoding.profile_for('admin@example.com', 'admin')
        self.assertFalse(encoding.is_admin(user))
        self.assertTrue(encoding.is_admin(admin))

if(__name__ == '__main__'):
    unittest.main()
