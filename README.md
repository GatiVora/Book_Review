
# Book Review App

This repository contains the backend implementation for a book review platform using FastAPI and MongoDB.


## Features

-User Authentication: Secure user registration and login with JWT authentication.

-Book Management: CRUD operations for managing books, including scraping data from Open Library.

-Review System: Allow users to post, update, and delete reviews for books.

-Pagination and Filtering: Implement pagination for book and review lists, with filtering options.

-Scheduler: Automate periodic scraping of book data to keep the database updated
## Configuration

Before running the project, set the following environment variables. Modify them according to your specific setup:



```bash
  mongodb_uri="mongodb+srv://<username>:<password>@<url>/farmstack?retryWrites=true&w=majority"
```
    

## Run It


Run the code with the following command:



```bash
uvicorn main:app --reload
```
