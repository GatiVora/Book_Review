from fastapi import Depends,HTTPException
from jwttoken import verify_token
from fastapi.security import OAuth2PasswordBearer
from starlette import status

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

#function to get current user based on JWT token
def get_current_user(token: str = Depends(oauth2_scheme)):
	credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
	return verify_token(token,credentials_exception)