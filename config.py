import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///auth_app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOG_FILE = 'auth_logs.json'