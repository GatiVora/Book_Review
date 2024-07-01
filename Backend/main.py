from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request,status,Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from hashing import Hash
from jwttoken import create_access_token
from auth import get_current_user
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from models import User , Login , Token ,TokenData,Book
from models import Review, ReviewUpdate
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from jwttoken import SECRET_KEY,ALGORITHM
from typing import List
import requests
import httpx
import asyncio
from bs4 import BeautifulSoup

app = FastAPI()
origins = [
    "http://localhost:3000",
    "http://localhost:8080",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

mongodb_uri = 'mongodb+srv://admin:admin@cluster.xfybzay.mongodb.net/?retryWrites=true&w=majority&appName=Cluster'
port = 8000
client = MongoClient(mongodb_uri, port)
db = client["Book_Review"]


@app.get("/")
def read_root(current_user:User = Depends(get_current_user)):
	return {"data":"Hello "}

#endpoint to register a user
@app.post('/register')
def create_user(request:User):
	hashed_pass = Hash.bcrypt(request.password)
	user_object = dict(request)
	user_object["password"] = hashed_pass
	user_id = db["users"].insert_one(user_object)
	print(user_id)
	return {"res":"created"}

#endpoint for user login
@app.post('/login')
def login(request:OAuth2PasswordRequestForm = Depends()):
	user = db["users"].find_one({"username":request.username})
	if not user:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail = f'No user found with this {request.username} username')
	if not Hash.verify(user["password"],request.password):
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail = f'Wrong Username or password')
	access_token = create_access_token(data={"sub": user["username"] })
	return {"access_token": access_token, "token_type": "bearer"}

#endpoint to get current logged in user
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db["users"].find_one({"username": token_data.username})
    if user is None:
        raise credentials_exception
    return User(**user)

#endpoint to get current user details
@app.get('/user/me')
def get_current_user_id(current_user: User = Depends(get_current_user)):
    user = db["users"].find_one({"username": current_user.username})
    if user:
        return {"user_id": str(user["_id"])}
    else:
        raise HTTPException(status_code=404, detail="User not found")

#endpoint to post reviews
@app.post('/reviews', status_code=201)
def create_review(review: Review, current_user: User = Depends(get_current_user)):
    review.user_id = current_user.username
    review_dict = review.dict()
    db["reviews"].insert_one(review_dict)
    return {"res": "Review created"}

#endpoint to get all reviews
@app.get('/reviews')
def get_reviews(page: int = 1, size: int = 10, current_user: User = Depends(get_current_user)):
    skips = size * (page - 1)
    reviews = list(db["reviews"].find().skip(skips).limit(size))
    return {"reviews": reviews}

#endpoint to get review by id
@app.get('/reviews/{review_id}')
def get_review(review_id: str, current_user: User = Depends(get_current_user)):
    review = db["reviews"].find_one({"_id": review_id})
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    return review

#endpoint to update review
@app.put('/reviews/{review_id}')
def update_review(review_id: str, review: ReviewUpdate, current_user: User = Depends(get_current_user)):
    review_dict = {k: v for k, v in review.dict().items() if v is not None}
    db["reviews"].update_one({"_id": review_id}, {"$set": review_dict})
    return {"res": "Review updated"}

#endpoint to delete a review
@app.delete('/reviews/{review_id}', status_code=204)
def delete_review(review_id: str, current_user: User = Depends(get_current_user)):
    db["reviews"].delete_one({"_id": review_id})
    return {"res": "Review deleted"}


#Function to scrape Open Library's trending books
def scrape_open_library_trending_books():
    url = 'https://openlibrary.org/trending/daily'
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        books = []
        for book_elem in soup.select('.booktitle'):
            title_elem = book_elem.find('a', class_='results')
            if title_elem:
                title = title_elem.text.strip()
                link = title_elem['href']
                books.append({'title': title, 'link': link})
        return books
    else:
        return None

#Store scraped books in MongoDB
def store_books_in_mongodb(books):
    if books:
        for book in books:
            db["books"].update_one(
                {'title': book['title']},
                {'$set': book},
                upsert=True
            )

#endpoint to scrape and store books
@app.post("/scrape_books", status_code=201)
def scrape_and_store_books():
    books = scrape_open_library_trending_books()
    if books:
        store_books_in_mongodb(books)
        return {"message": "Books scraped and stored successfully"}
    else:
        return {"message": "Failed to scrape books"}

#endpoint to retrieve scraped books
@app.get("/books", response_model=List[Book])
def get_books(page: int = Query(1, description="Page number"), size: int = Query(10, description="Page size")):
    skip = (page - 1) * size
    books = list(db["books"].find().skip(skip).limit(size))
    return books
