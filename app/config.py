# app/config.py
import os
from datetime import timedelta

class Config:
    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-this-in-production')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_ALGORITHM = 'HS256'
    
    # Database Configuration
    DB_HOST = os.environ.get('POSTGRES_HOST', 'db')
    DB_PORT = os.environ.get('POSTGRES_PORT', '5432')
    DB_NAME = os.environ.get('POSTGRES_DB', 'corebank')
    DB_USER = os.environ.get('POSTGRES_USER', 'postgres')
    DB_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'postgres')
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'app.log')
    
    # Security Configuration
    BCRYPT_LOG_ROUNDS = 12
