import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 's3cureR@ndomString!2024')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'd1ff3r3ntR@nd0mString!2024')
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/loan_management')
    
    # Email Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'preetidesai6363@gmail.com')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'hyxqnrqyyqgjllrc')
