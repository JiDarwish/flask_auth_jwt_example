# Configuration for the app
from datetime import timedelta

JWT_SECRET_KEY = 'super-secret'
JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=100)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=365)


SQLALCHEMY_DATABASE_URI = 'mysql://root:124578FF@localhost/jwt'
SQLALCHEMY_TRACK_MODIFICATIONS = False