from functools import wraps
import json
import re
from flask import Flask, request, abort, g
from jose import jwt

app = Flask(__name__)

uri = 'http://localhost:5000'

with open('../../id.json') as f:
    jwks = json.loads(f.read())

pattern = re.compile(r'^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$')

acl = ['example-python-flask']

def authorize(function):
    @wraps(function)
    def decorator(*args, **kwargs):
        try:
            token = pattern.findall(request.headers['Authorization'])[0]
            headers = jwt.get_unverified_header(token)
            keys = [k for k in jwks['keys'] if k['kid'] == headers['kid']]
            g.identity = {
                'headers': headers,
                'claims': jwt.decode(token, keys, 'RS256', audience=uri)
            }
        except Exception:
            abort(401)
        if headers['kid'][:-9] not in acl:
            abort(403)
        return function(*args, **kwargs)
    return decorator

@app.route('/')
@authorize
def index():
    return 'welcome back {}'.format(g.identity)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
