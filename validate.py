import datetime
from jose import jwk
import json
import unittest

JWKS_FILENAME = 'id.json'
KEY_KID_FORMAT = r'^[a-zA-Z0-9-]+-[0-9]{8}$'
KEY_TYPE = 'RSA'
KEY_ALGORITHM = 'RS256'

class Validate(unittest.TestCase):

    jwks = None

    def setUp(self):
        with open(JWKS_FILENAME, 'r') as f:
            self.jwks = json.loads(f.read())

    def validate_date(self, date):
        try:
            return datetime.datetime.strptime(date, '%Y%m%d')
        except ValueError:
            return None

    def validate_jwk(self, key):
        try:
            return jwk.construct(key, KEY_ALGORITHM)
        except jwk.JWKError:
            return None

    def test_validate_jwks(self):
        with open(JWKS_FILENAME, 'r') as f:
            self.jwks = json.loads(f.read())
        self.assertIn('keys', self.jwks, 'keys property not found')
        self.assertIsNotNone(self.jwks['keys'], 'keys value is null')
        for key in self.jwks['keys']:
            self.assertIn('kid', key, 'kid property not found')
            self.assertRegex(key['kid'], KEY_KID_FORMAT, 'kid has an invalid format')
            self.assertIsNotNone(self.validate_date(key['kid'][-8:]), 'kid postfix has invalid date')
            self.assertEqual(1, len([k for k in self.jwks['keys'] if k['kid'] == key['kid']]), 'kid is used in multiple keys')
            self.assertIn('kty', key, 'kty property not found')
            self.assertEqual(KEY_TYPE, key['kty'], 'kty value is invalid')
            self.assertIn('alg', key, 'alg property not found')
            self.assertEqual(KEY_ALGORITHM, key['alg'], 'alg value is invalid')
            self.assertIn('e', key, 'e property not found')
            self.assertIsNotNone(key['e'], 'e value is null')
            self.assertIn('n', key, 'n property not found')
            self.assertIsNotNone(key['n'], 'n value is null')
            self.assertIsNotNone(self.validate_jwk(key), 'cannot construct public key')

if __name__ == '__main__':
    unittest.main()
