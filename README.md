# Service Authentication

## Install

```
python3 -m venv .
python3 -m pip install -r requirements.txt
```

## Usage

Generate RSA256 private key PEM and add it's public key to `id.json`:
```
python3 generate.py --kid example-key-20171229
```

Clients create JWTs signed with the generated PEM:
```
from jose import jwt
claims = {'sub': '0'}
headers = {'kid': 'example-key-20171229'}
token = jwt.encode({}, pem, 'RS256', headers)
```

And services verify JWTs using the JWKS file:
```
from jose import jwt
with open('id.json', 'r') as f:
    jwks = json.loads(f.read())
claims = jwt.decode(token, jwks, 'RS256')
```
