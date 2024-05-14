import time
import os
from hashlib import sha256
from base64 import urlsafe_b64encode, urlsafe_b64decode
from flask import Flask, request, Response
from flask import jsonify

from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import unset_jwt_cookies

from flask_cors import CORS

from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies", "json", "query_string"]

app.config["JWT_COOKIE_SECURE"] = False

app.config["JWT_SECRET_KEY"] = "super-secret"

db = SQLAlchemy(app)

jwt = JWTManager(app)

CORS(app, supports_credentials=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(128))
    salt = db.Column(db.String(128))

    def set_password(self, password):
        """Create a password hash using SHA-256 and a new salt."""
        salt = os.urandom(16)
        salted_password = salt + password.encode('utf-8')
        hash_digest = sha256(salted_password).digest()
        self.salt = urlsafe_b64encode(salt).decode('utf-8')
        self.password_hash = urlsafe_b64encode(hash_digest).decode('utf-8')

    def check_password(self, password):
        """Verify the password with the stored hash and salt."""
        salt = urlsafe_b64decode(self.salt.encode('utf-8'))
        salted_password = salt + password.encode('utf-8')
        new_hash = sha256(salted_password).digest()
        return self.password_hash == urlsafe_b64encode(new_hash).decode('utf-8')

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username or email already exists'}), 409
    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/time')
def get_current_time():
	return {'time': time.time()}

@app.route("/login_with_cookies", methods=["POST"])
def login_with_cookies():
    username = request.json.get('username')
    password = request.json.get('password')
    user = User.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        return jsonify({'msg': 'Bad username or password'}), 401
    access_token = create_access_token(identity=username)
    response = jsonify({'login': True})
    set_access_cookies(response, access_token)
    return response

@app.route("/logout_with_cookies", methods=["POST"])
def logout_with_cookies():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response

@app.route("/protected", methods = ["GET", "POST"])
@jwt_required()
def protected():
	return jsonify(foo="bar")

@app.route('/validate', methods=['GET'])
@jwt_required(optional=False)
def validate():
    current_user = get_jwt_identity()
    print("this is current_user", current_user)
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    app.run(debug=True)
