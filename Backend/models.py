from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request,status
from fastapi.responses import JSONResponse
from pydantic import BaseModel,Field
from typing import List

class User(BaseModel):
    username: str
    password: str

class Login(BaseModel):
	username: str
	password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class Review(BaseModel):
    book_id: str
    rating: int
    comment: str
    user_id: Optional[str] = None

class ReviewUpdate(BaseModel):
    rating:Optional[str] =None
    comment:Optional[str] = None


class Book(BaseModel):
    title: str
    link:str
    author:str
    published_year:str
