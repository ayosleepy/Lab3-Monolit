import os

class Config:
    SECRET_KEY = 'dev-secret-key'
    DATABASE = 'microblog.db'
    UPLOAD_FOLDER = 'static/uploads'
    POSTS_PER_PAGE = 10