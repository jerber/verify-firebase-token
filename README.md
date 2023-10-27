# verify-firebase-token

Just one file that verifies Firebase Authentication ID tokens, replacing firebase_admin.verify_token.

I made this because:

1) firebase_admin is a massive library and I was only using it for decoding jwt tokens.
2) firebase_admin.verify_token constantly calls Google's servers for CERTS. I made an in memory cache for this.

## Dependencies
1) `PyJWT` for jwt verifying and parsing
2) `cryptography` for extracting the public keys from Google's certificates
3) `requests` for getting Google's certificates

## Installation
```
$ pip install verify-firebase-token
```

## Verifying tokens
```python
from verify_firebase_token import verify_token

result = verify_token("<TOKEN>", "<FIREBASE_PROJECT_ID>")
```

The result is a dictionary with the JWT payload. If the token cannot be verified, the raw JWT errors will be raised.