from fastapi import FastAPI
from fastapi.responses import JSONResponse
from jose import jwt, jwk, constants
from datetime import datetime, timedelta, timezone
from thriftParser import parse_thrift
import os

app = FastAPI()
 
# Load the private and public keys
with open("private_key.pem", "rb") as f:
    private_key = jwk.RSAKey(algorithm=constants.Algorithms.RS256, key=f.read())

with open("public_key.pem", "rb") as f:
    public_key = jwk.RSAKey(algorithm=constants.Algorithms.RS256, key=f.read())

# Endpoint to get the public key in JWKS format
@app.get("/.well-known/jwks.json")
def get_public_key():
    jwks = {"keys": [public_key.to_dict()]}
    return JSONResponse(content=jwks)

# Endpoint to generate a token
@app.post("/token")
def generate_token():
    expiration = datetime.now(timezone.utc) + timedelta(hours=1)
    scopes = ["spud.read"]
    token = jwt.encode({"exp": expiration, "scopes": scopes}, private_key, constants.Algorithms.RS256)
     
    return JSONResponse(content={
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 3600
    })

@app.get("/scopes/{service_name}/{method_name}")
def get_scopes(service_name: str, method_name: str):
    file_path = os.path.join(os.path.dirname(__file__), os.getenv("THRIFT_PATH", "../PotatoService.thrift"))
    thrift = parse_thrift(file_path)

    try:
        scopes = thrift["services"][service_name][method_name]["annotations"].get("scope", "")
    except KeyError:
        return JSONResponse(content={"detail": "Service method not found"}, status_code=404)
    
    return JSONResponse(content={ "scopes": scopes })
