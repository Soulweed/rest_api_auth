#!/usr/bin/env python
import os
import time
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()



class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        return (jsonify({'username': username, 'status':'User Already Exist'}), 201) # existing user

    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username, 'status':'User Added'}), 200,
            {'Location': url_for('get_user', id=user.id, _external=True)}) # <-- This part return Location of User Id in Header


@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    else:
        # User valid now check password
        flag = verify_password(username, password)
        if flag == True:
            print("--> App Debug : User Verified")
            # -- Now get Token
            token = g.user.generate_auth_token(600)
            return jsonify({'token': token.decode('ascii'), 'duration': 600})

        else:
            abort(401)


@app.route('/api/resource', methods=['POST']) # use this method for access with authorized
# @auth.login_required # -- decorate for New permission to use resource
def get_resource():
    # -- TODO : This is a function for validate authorize of user that allowed to access resource
    token = request.json.get('token')
    if token is None:
        abort(401)

    user = User.verify_auth_token(token)
    if not user:
        return jsonify({'Error': 'Token not valid'})
    
    return jsonify({'data': 'Hello, %s!' % user.username})


@app.route('/') # -- Check Status API
def check_instant():
    print("OK")
    return jsonify({'status': 'API is Work!!'})


if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)
