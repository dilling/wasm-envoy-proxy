from fastapi import FastAPI
from fastapi.responses import JSONResponse
from jose import jwt
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode

app = FastAPI()
 
# Load the private and public keys
with open("private_key.pem", "rb") as f:
    private_key = f.read()

with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

# Convert the public key to JWKS format
def get_jwks():
    public_numbers = public_key.public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": "1",
        "use": "sig",
        "alg": "RS256",
        "n": urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
        "e": urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')
    }
    return {"keys": [jwk]}

# Endpoint to get the public key in JWKS format
@app.get("/.well-known/jwks.json")
def get_public_key():
    return JSONResponse(content=get_jwks())

# Endpoint to generate a token
@app.post("/token")
def generate_token():
    expiration = datetime.now(timezone.utc) + timedelta(hours=1)
    token = jwt.encode({"exp": expiration}, private_key, algorithm='RS256')
 
    return JSONResponse(content={
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 3600
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=80)