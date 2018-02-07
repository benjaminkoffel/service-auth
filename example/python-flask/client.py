import time
import calendar
import uuid
import requests
import jwt

uri = 'http://localhost:5000'

kid = 'example-python-flask-20180101'

with open(kid + '.pem', 'r') as f:
    pem = f.read()

def token(audience):
    timestamp = calendar.timegm(time.gmtime())
    claims = {
        'jti': str(uuid.uuid4()),
        'aud': audience,
        'iat': timestamp,
        'exp': timestamp + 60
    }
    headers = {'kid': kid}
    return jwt.encode(claims, pem, 'RS256', headers).decode('utf-8')

def main():
    while True:
        headers = {'Authorization': 'Bearer ' + token(uri)}
        response = requests.get(uri, headers=headers)
        print(response.status_code, response.text)
        time.sleep(1)

if __name__ == '__main__':
    main()
