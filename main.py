import jwt  # PyJWT
import uuid
import hashlib
from urllib.parse import urlencode

# query는 dict 타입입니다.
m = hashlib.sha512()
m.update(urlencode(query).encode())
query_hash = m.hexdigest()

payload = {
    'access_key': 'VjlOSgs52zhV0l3dvz1liF2aPJjTHy0AqbrjN0X2',
    'nonce': str(uuid.uuid4()),
    'query_hash': query_hash,
    'query_hash_alg': 'SHA512',
}

jwt_token = jwt.encode(payload, 'NeRJ2KiWueGNW6fW8W8WHT1H82nwBL0udNKTUYfx')
authorization_token = 'Bearer {}'.format(jwt_token)