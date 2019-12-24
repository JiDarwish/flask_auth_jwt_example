from flask import Flask, jsonify, request
from flask_jwt_extended import (JWTManager, jwt_required, jwt_refresh_token_required, fresh_jwt_required, create_access_token, create_refresh_token, get_jwt_identity)
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import bcrypt
import config


app = Flask(__name__)
app.config.from_object(config)

jwt = JWTManager(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)

# Makes sure all tables are created before run
@app.before_first_request
def create_tables():
  db.create_all()

# User table
class User(db.Model):
  __tablename__ = 'users'
  id = db.Column('id', db.Integer, primary_key=True)
  name = db.Column('name', db.String(120))
  username = db.Column('username', db.String(120), unique=True)
  password = db.Column('password', db.String(120), unique=True)

  def __init__(self, name, username, password):
    self.name = name
    self.username = username
    self.password = User.get_hashed_password(password)

  def __repr__(self):
    return f'user {self.username}'

  # Create password hash
  @staticmethod
  def get_hashed_password(plain_text_password):
    return bcrypt.hashpw(str(plain_text_password).encode('utf-8'), bcrypt.gensalt())
  
  # Validate password hash
  @staticmethod
  def check_password(plain_text_password, hashed_password):
    return bcrypt.checkpw(str(plain_text_password).encode('utf-8'), str(hashed_password).encode('utf-8'))


# Login route returns a FRESH access_token and a refresh_token
@app.route('/login', methods=['POST'])
def login():
  data = request.json
  username = data['username']
  password = data['password']

  user = User.query.filter(User.username == username).first()
  
  if not user:
    return jsonify({'msg': f'No user found with the given username {username}'}), 400
  
  if not User.check_password(password, user.password):
    return jsonify({'msg': f'password is wrong for user {username}'}), 400
  
  # Generate jwt token and send to user
  access_token = create_access_token(identity=user.username, fresh=True)
  refresh_token = create_refresh_token(identity=user.username)
  return jsonify({'access_token': access_token, 'refresh_token': refresh_token, 'type': 'Bearer'}), 200


# Sign up for this example it only returns a success message (maybe in a real app it would redirect a user to the login screen)
@app.route('/signup', methods=['POST'])
def signup():
  name = request.json['name']
  username = request.json['username']
  password = request.json['password']

  user = User(name, username, password)
  db.session.add(user)
  db.session.commit()
  return jsonify({'msg': f'User {username} was created successfully'}), 201


# Protect a view with jwt_required, which requires a valid access token
# in the request to access.
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
  # Access the identity of the current user with get_jwt_identity
  current_user = get_jwt_identity()
  return jsonify(logged_in_as=current_user), 200


# Refreshes the access token and returns a non-fresh token
@app.route('/refresh', methods=['GET'])
@jwt_refresh_token_required
def refresh_token():
  '''
    To this url you need to send the Authorization header and the refresh token so that the server can verify it and generate a new access_token
  '''
  current_user = get_jwt_identity()
  # return a non-fresh token for the user
  new_token = create_access_token(identity=current_user, fresh=False)
  return {'access_token': new_token}, 200

# Critical endpoint that requires a FRESH access_token
@app.route('/critical')
@fresh_jwt_required
def critical():
  current_user = get_jwt_identity()
  return jsonify({'msg': f'Well you\'ve got a fresh token mr {current_user}'})

  
if __name__ == '__main__':
  app.run(debug=True)
