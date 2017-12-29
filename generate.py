import argparse
import base64
import json
from Crypto.PublicKey import RSA
from jose import jwk, jwt
import datetime
import re

JWKS_FILENAME = 'id.json'
KEY_KID_FORMAT = r'^[a-zA-Z0-9-]+-[0-9]{8}$'
KEY_TYPE = 'RSA'
KEY_ALGORITHM = 'RS256'

def kid_regex_type(s, pat=re.compile(KEY_KID_FORMAT)):
    if not pat.match(s):
        raise argparse.ArgumentTypeError
    return s

def validate_date(text):
    try:
        datetime.datetime.strptime(text, '%Y%m%d')
        return True
    except ValueError:
        return False

def validate_jwks(jwks):
    assert 'keys' in jwks, 'keys property not found'
    assert jwks.keys is not None, 'keys value is null'
    for key in jwks['keys']:
        assert 'kid' in key, 'kid property not found'
        assert re.match(KEY_KID_FORMAT, key['kid']), 'kid has invalid format'
        assert validate_date(key['kid'][-8:]), 'kid postfix has invalid date'
        assert len([k for k in jwks['keys'] if k['kid'] == key['kid']]) == 1, 'kid is not unique'
        assert 'kty' in key, 'kty property not found'
        assert key['kty'] == KEY_TYPE, 'kty value is invalid'
        assert 'alg' in key, 'alg property not found'
        assert key['alg'] == KEY_ALGORITHM, 'alg value is invalid'
        assert 'e' in key, 'e property not found'
        assert key['e'] is not None, 'e value is null'
        assert 'n' in key, 'n property not found'
        assert key['n'] is not None, 'n value is null'
        assert jwk.construct(key, KEY_ALGORITHM), 'cannot construct public key'

def validate_signing(pem, pub):
    jwt.decode(jwt.encode({}, pem, KEY_ALGORITHM), pub, KEY_ALGORITHM)

def b64_bigendian(i):
    return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8,'big')).decode('utf-8')

def export_jwk(kid, pem):
    key = RSA.importKey(pem)
    return {
        'kid': kid,
        'kty': KEY_TYPE,
        'alg': KEY_ALGORITHM,
        'e': b64_bigendian(key.e),
        'n': b64_bigendian(key.n)
    }

def generate_pem():
    key = RSA.generate(2048)
    return key.exportKey('PEM')

def main(kid):
    with open(JWKS_FILENAME, 'r') as f:
        jwks = json.loads(f.read())
    validate_jwks(jwks)
    pem = generate_pem()
    pub = export_jwk(kid, pem)
    validate_signing(pem, pub)
    jwks['keys'].append(pub)
    with open(JWKS_FILENAME, 'w') as f:
        f.write(json.dumps(jwks, indent=4))
    print(pem.decode('utf-8'))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate RSA256 PEM and append public JWK to id.json')
    parser.add_argument('--kid', type=kid_regex_type, default='default-kid-20171228', help='key identifier')
    args = parser.parse_args()
    main(args.kid)
