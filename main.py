import jwt

from datetime import datetime
from datetime import timedelta

from fastapi import FastAPI

from fastapi import status
from fastapi import Depends

from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm

app = FastAPI()

"""
grant type
scope
client_id
client_secret
"""

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

SECRET_KEY = 'TallerCF'

def generate_access_token(username, expiration_days=7):
    data = {
        'username': username, 
        'exp': datetime.utcnow() + timedelta(days=expiration_days) 
    }

    return jwt.encode(data, SECRET_KEY, algorithm='HS256')


def decode_access_token(access_token):
    try:
        return jwt.decode(access_token, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        return None


def token_is_valid(token):
    if token and token.get('username') and token.get('exp'):
        return datetime.fromtimestamp(token['exp']) > datetime.utcnow()
    
    return False


async def get_current_user(token: str = Depends(oauth2_scheme)):
    data = decode_access_token(token)

    if  token_is_valid(data):
        return data['username']
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

@app.post('/login')
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) 
    """

    return {
        'access_token': generate_access_token(form_data.username),
        'token_type': 'bearer'
    } 

@app.get('/home')
async def home(username: str = Depends(get_current_user)):
    return {'username': username}