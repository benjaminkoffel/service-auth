import argparse
import base64
from Crypto.PublicKey import RSA
import datetime
from jose import jwt
import json
import re

JWKS_FILENAME = 'id.json'
KEY_KID_FORMAT = r'^[a-zA-Z0-9-]+-[0-9]{8}$'
KEY_TYPE = 'RSA'
KEY_ALGORITHM = 'RS256'

def validate_keypair(pem, pub):
    try:
        return jwt.decode(jwt.encode({}, pem, KEY_ALGORITHM), pub, KEY_ALGORITHM) == {}
    except jwt.JWTError:
        print('ERROR: could not encode/decode using keypair')
        return True

def b64_bigendian(i):
    return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8,'big')).decode('utf-8')

def generate_keypair(kid):
    key = RSA.generate(2048)
    private = key.exportKey('PEM')
    public = {
        'kid': kid,
        'kty': KEY_TYPE,
        'alg': KEY_ALGORITHM,
        'e': b64_bigendian(key.e),
        'n': b64_bigendian(key.n)
    }
    return private, public

def validate_kid(jwks, kid):
    if not re.match(KEY_KID_FORMAT, kid):
        print('ERROR: invalid kid parameter, format must match regex', KEY_KID_FORMAT)
        return False
    try:
        datetime.datetime.strptime(kid[-8:], '%Y%m%d')
    except ValueError:
        print('ERROR: invalid kid parameter, version postfix must be a valid date')
        return False
    if any(k['kid'] == kid for k in jwks['keys']):
        print('ERROR: invalid kid parameter, kid is already in use')
        return False
    if any(k['kid'][:-8] == kid[:-8] and int(k['kid'][-8:]) > int(kid[-8:]) for k in jwks['keys']):
        print('ERROR: invalid kid parameter, version postfix must be incremental')
        return False
    return True

def main(kid):
    with open(JWKS_FILENAME, 'r') as f:
        jwks = json.loads(f.read())
    if not validate_kid(jwks, kid):
        return
    pem, pub = generate_keypair(kid)
    if not validate_keypair(pem, pub):
        return
    jwks['keys'].append(pub)
    with open(JWKS_FILENAME, 'w') as f:
        f.write(json.dumps(jwks, indent=4))
    print(pem.decode('utf-8'))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate RSA256 PEM and append public key JWK to id.json')
    parser.add_argument('--kid', required=True, help='key identifier')
    args = parser.parse_args()
    main(args.kid)
