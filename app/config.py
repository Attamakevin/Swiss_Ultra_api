import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'you-will-never-guess')
    # Use the external URL for production and fallback to local SQLite for development
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://swissultradb_user:wSrfUaX6Kl80NXAFgNrX5S8g7pE8zcTt@dpg-cro4us88fa8c738npnn0-a.oregon-postgres.render.com/swissultradb')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'super-secret')

