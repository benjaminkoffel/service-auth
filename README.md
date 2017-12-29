# Service Authentication

Example of authentication using client signed JWTs.

Clients generate a key pair and then submit public key in updated JWKS file via pull request.

Authentication system administrators review pull requests and merge/reject as required.

Client requests are then appended with JWT bearer tokens signed by the private key.

Services pull and cache the JWKS file and authenticate clients by verifying the token signature.

Subsequently, authorization can be applied via an ACL containing a list of `kid` values minus version date.

Key rotation is achieved by generating a key with same `kid` and newer version date.

Obsolete keys can then be deleted at a later date once the new key has propagated.

## Benefits
- very limited infrastructure overhead
- identity is centralised and can be verified and audited
- authorization can be controlled by services
- key rotation initiated by client, does not impact services and creates no downtime
- services only dependency is on `id.json` which can be cached at the edge and in the service
- services highly tolerant to failure due to ability to authenticate using locally replicated `id.json`
- clients highly tolerant to failure due to signing of tokens using locally stored private key

## Limitations
- no audit logs for when tokens are created
- no ability to centralize token format or content ie. expiration

## Installation

```
python3 -m venv .
python3 -m pip install -r requirements.txt
```

## Usage

Generate RSA256 private key PEM and add it's public key to `id.json`:
```
python3 generate.py --kid example-key-20171229 > id.pem
```

JWKS can be validated before merge or deployment:
```
python3 validate.py
```

Clients create JWTs signed with the generated PEM:
```
import json
from jose import jwt
with open('id.pem', 'r') as f:
    pem = f.read()
claims = {'sub': '0'}
headers = {'kid': 'example-key-20171229'}
token = jwt.encode(claims, pem, 'RS256', headers)
```

Services authenticate by verifying JWT with JWKS:
```
import json
from jose import jwt
with open('id.json', 'r') as f:
    jwks = json.loads(f.read())
headers = jwt.get_unverified_header(token)
key = [k for k in jwks['keys'] if k['kid'] == headers['kid']]
claims = jwt.decode(token, key, 'RS256')
```

Services enforce authorization via ACL:
```
from jose import jwt
acl = ['example-key']
headers = jwt.get_unverified_header(token)
assert headers['kid'][:-9] in acl
```
