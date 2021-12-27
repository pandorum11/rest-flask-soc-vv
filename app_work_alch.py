from flask import Flask, request, jsonify, make_response

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy import ForeignKeyConstraint, ForeignKey
from sqlalchemy.sql import func

from werkzeug.security import generate_password_hash, check_password_hash

from datetime import datetime

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import current_user

from config import Config

# ----INITIATION CONFIG-----------------------------------------------------

def create_app():

    app = Flask(__name__)
    app.config.from_object(Config)
    return app

# ----INITIATION APP--------------------------------------------------------

app = create_app()

# ----INITIATION JWT TOKEN AUTHENTIFICATION---------------------------------

jwt = JWTManager(app)

# ----DATABASE DECLARATION BLOCK--------------------------------------------

# cmd command for base create

# from app_work_alch import Base, engine
# Base.metadata.create_all(bind=engine)

engine = create_engine(
                        app.config['SQLALCHEMY_DATABASE_URI'],
                        connect_args={'check_same_thread': False})

db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))

Base = declarative_base()
Base.query = db_session.query_property()

# database uses constraint keys for talbes connections
# which includes cascade changes in linked tables


class Users(Base):

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), unique=True, nullable=False)
    password = Column(String(50), nullable=False)
    last_login = Column(DateTime, nullable=False,
                        default=datetime.utcnow())
    last_request = Column(DateTime, nullable=False,
                          default=datetime.utcnow())


class Posts(Base):

    __tablename__ = 'posts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(50), nullable=False)
    body = Column(String(1000), nullable=False)
    created = Column(DateTime, nullable=False, default=datetime.utcnow())
    author_id = Column(Integer)
    __table_args__ = (ForeignKeyConstraint([author_id],
        [Users.id]), {})


class Likes(Base):

    __tablename__ = 'likes'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer)
    post_id = Column(Integer,ForeignKey('posts.id'))
    __table_args__ = (ForeignKeyConstraint([user_id],
        [Users.id]), {})
    like_or_dislike = Column(Boolean)
    added_at = Column(DateTime, nullable=False,
                      default=datetime.utcnow())


# -------------------------------------------------------

# Register a callback function that takes whatever object is passed in as the
# identity when creating JWTs and converts it to a JSON serializable format.

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

# Register a callback function that loads a user from your database whenever
# a protected route is accessed. This should return any python object on a
# successful lookup, or None if the lookup failed for any reason (for example
# if the user has been deleted from the database).

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return Users.query.filter_by(id=identity).one_or_none()

# ----NON DEFENDED ROUTES---------------------------------------------------


@app.route('/register', methods=['POST'])
def signup_user():
    """
    Function is not defended, supposes for debug only
    """
    data = request.get_json()
    name = data['name']

    user = Users.query.filter_by(name=name).first()

    if not user:

        hashed_password = generate_password_hash(data['password'], method='sha256')

        new_user = Users(name=name, password=hashed_password)
        db_session.add(new_user)
        db_session.commit()

        return jsonify({'message':\
         f'The user with name {name} registered successfully'})

    else:
        return jsonify({'message':\
         f'The user with name {name} already exists'})


@app.route('/login', methods=['GET', 'POST'])
def login_user():

    auth = request.authorization
    user = Users.query.filter_by(name=auth.username).first()

    if not auth or not auth.username or not auth.password or not user:
        return make_response({'Error': 'Authorization failed'})

    if check_password_hash(user.password, auth.password):
        user.last_login = datetime.utcnow()
        db_session.commit()
        token = create_access_token(identity=user)
        return jsonify({'token': token})

    else:
        return jsonify({'Error': 'Bad username or password'})


# ----JWT DEFENDED ROUTES---------------------------------------------------


@app.route('/post', methods=['POST'])
@jwt_required()
def create_post():

    jwt = get_jwt_identity()
    user = Users.query.filter_by(id=jwt).first()
    user.last_request = datetime.utcnow()

    data = request.get_json()

    new_post = Posts(title=data['title'], body=data['body'], author_id=jwt)
    db_session.add(new_post)

    db_session.commit()

    return jsonify({'message': 'New post created'})


@app.route('/posts', methods=['GET'])
@jwt_required()
def get_posts():
    """
    Returns all posts.
    """

    jwt = get_jwt_identity()
    user = Users.query.filter_by(id=jwt).first()
    user.last_request = datetime.utcnow()
    db_session.commit()

    posts = Posts.query.all()

    output = []

    for post in posts:

        post_data = {}
        post_data['id'] = post.id
        post_data['title'] = post.title
        post_data['body'] = post.body
        post_data['created'] = post.created
        output.append(post_data)

    return jsonify({'list_of_posts': output})


@app.route('/post/<post_id>/<like_or_dislike>', methods=['POST'])
@jwt_required()
def like_post(post_id, like_or_dislike):
    """
    Example:
    http://.../post/1/like
    http://.../post/1/dislike

    Takes 2 parameters number of post and like or dislike mark
    """

    # validation commands
    if like_or_dislike != 'like' and like_or_dislike != 'dislike':
        return jsonify({'Error': 'wrong input'})

    jwt = get_jwt_identity()
    user = Users.query.filter_by(id=jwt).first()
    user.last_request = datetime.utcnow()
    db_session.commit()

    # if there is no such post
    post = Posts.query.filter_by(id=post_id).first()
    if not post:
        return jsonify({'Error': 'Post does not exist'})

    like_ready = Likes.query.filter_by(
        user_id=get_jwt_identity(), post_id=post_id).first()

    message = ''

    # logic:

    # if we have ready DB row for current user&post like_or_dislike
    # check it if there is same mark - leave alone
    # if opposite - delete row

    if like_ready:

        if like_ready.like_or_dislike == False:
            if like_or_dislike == 'like':
                db_session.delete(like_ready)
                db_session.commit()
                message = 'Your dislike was deleted'
            if like_or_dislike == 'dislike':
                message = 'Post is alredy disliked once'

        if like_ready.like_or_dislike == True:
            if like_or_dislike == 'dislike':
                db_session.delete(like_ready)
                db_session.commit()
                return jsonify({'message': 'Your like was deleted'})
            if like_or_dislike == 'like':
                return jsonify({'message': 'Post is alredy liked once'})

    # if there is not like_or_dislike row in db
    # create it with valid mark

    if not like_ready:

        if like_or_dislike == 'like':
            flag = True
            message = f'You liked post with id {post_id}'
        if like_or_dislike == 'dislike':
            flag = False
            message = f'You disliked post with id {post_id}'

        new_like_dislike = Likes(user_id=jwt, post_id=post_id, like_or_dislike=flag)

        db_session.add(new_like_dislike)
        db_session.commit()   

    return jsonify({'message': message})


@app.route('/getinfo', methods=['GET'])
@jwt_required()
def get_current_user_info_endpoint():
    """
    get current user information
    this will not make mark in db as last request
    """
    jwt = get_jwt_identity()
    user = Users.query.filter_by(id=jwt).first()

    # for making mark last login in db - pls discomment next code:
    # user.last_request = datetime.utcnow()

    user_data = {}
    user_data['id'] = user.id
    user_data['last_login'] = user.last_login
    user_data['last_request'] = user.last_request
    user_data['name'] = user.name

    return jsonify({'user data': user_data})


@app.route('/api/analitics/', methods=['GET'])
@jwt_required()
def get_analiticst_all_likes():
    """
    This showing only likes statistics
    """

    jwt = get_jwt_identity()
    user = Users.query.filter_by(id=jwt).first()
    user.last_request = datetime.utcnow()

    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    # cheking date format
    try:
        datetime.strptime(date_from, '%Y-%m-%d')
        datetime.strptime(date_to, '%Y-%m-%d')
        if date_from > date_to:
            raise Exception
    except:
        return jsonify({'Error:': 'not valid time values'})

    # date time filter
    qry = db_session.query(Likes).\
        filter(func.date(Likes.added_at) >= func.date(date_from),
               func.date(Likes.added_at) <= func.date(date_to),
               Likes.like_or_dislike == True).all()

    db_session.commit()

    return jsonify({'All likes:': {'from': date_from,
                                   'to': date_to,
                                   'count': str(len(qry))}})

# --------------------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)
