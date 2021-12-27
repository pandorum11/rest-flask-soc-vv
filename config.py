import os
from datetime import timedelta

class Config(object):

    ################
    # Flask-Security
    ################

    DEBUG = True
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'Th1s1ss3cr3t'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///social_net_api_db_23.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
