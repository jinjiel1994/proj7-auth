# Laptop Service
import flask
import os
import pymongo
from flask import Flask, abort, request, jsonify, g, url_for, render_template
from flask_restful import Resource, Api

# Instantiate the app
from passlib.apps import custom_app_context as pwd_context
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from pymongo import MongoClient
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

# initialization
from werkzeug.utils import redirect

app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


client = MongoClient('db', 27017)
db_time = client.time


class listAll(Resource):
    def get(self):
        _items = db_time.time.find()
        items = [item for item in _items]

        return {'km': [item['km'] for item in items],
                'open': [item["open"] for item in items],
                'close': [item["close"] for item in items]
                }


class listOpenOnly(Resource):
    def get(self):
        _items = db_time.time.find()
        items = [item for item in _items]

        return {'open': [item["open"] for item in items]
                }


class listCloseOnly(Resource):
    def get(self):
        _items = db_time.time.find()
        items = [item for item in _items]

        return {'close': [item["close"] for item in items]
                }


class listAllcsv(Resource):
    def get(self):
        _items = db_time.time.find()
        items = [item for item in _items]
        csv = 'open, close\n'
        for item in items:
            csv += '%s, %s\n' % (item['open'], item['close'])
        csv = csv.strip('\n')
        csv = csv.split('\n')
        return csv


class listOpenOnlycsv(Resource):
    def get(self):

        top = flask.request.args.get("top", type=int)
        if top is None:
            _items = db_time.time.find()
        else:
            _items = db_time.time.find().sort("open", pymongo.ASCENDING).limit(top)

        items = [item for item in _items]
        csv = 'open\n'
        for item in items:
            csv += '%s\n' % item['open']
        csv = csv.strip('\n')
        csv = csv.split('\n')
        return csv


class listCloseOnlycsv(Resource):
    def get(self):
        _items = db_time.time.find()
        items = [item for item in _items]
        csv = 'close\n'
        for item in items:
            csv += '%s\n' % item['close']
        csv = csv.strip('\n')
        csv = csv.split('\n')
        return csv


class listAlljson(Resource):
    def get(self):
        _items = db_time.time.find()
        items = [item for item in _items]
        json = []
        for item in items:
            json.append({'km': item['km'],
                'open': item['open'],
                'close': item['close']
                })
        return json


class listOpenOnlyjson(Resource):
    def get(self):
        top = flask.request.args.get("top", type=int)
        if top is None:
            _items = db_time.time.find()
        else:
            _items = db_time.time.find().sort("open", pymongo.ASCENDING).limit(top)

        items = [item for item in _items]
        json = []
        for item in items:
            json.append({'km': item['km'],
                         'open': item['open']
                        })
        return json


class listCloseOnlyjson(Resource):
    def get(self):
        _items = db_time.time.find()
        items = [item for item in _items]
        json = []
        for item in items:
            json.append({'km': item['km'],
                         'close': item['close']
                        })
        return json


# Create routes
# Another way, without decorators
api.add_resource(listAll, '/listAll')
api.add_resource(listOpenOnly, '/listOpenOnly')
api.add_resource(listCloseOnly, '/listCloseOnly')
api.add_resource(listAllcsv, '/listAll/csv')
api.add_resource(listOpenOnlycsv, '/listOpenOnly/csv')
api.add_resource(listCloseOnlycsv, '/listCloseOnly/csv')
api.add_resource(listAlljson, '/listAll/json')
api.add_resource(listOpenOnlyjson, '/listOpenOnly/json')
api.add_resource(listCloseOnlyjson, '/listCloseOnly/json')


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user


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


@app.route('/')
def index():
    return render_template('register.html')


@app.route('/api/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['pass']
    if username is '' or password is '':
        abort(400)  # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)  # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username, 'Location': user.id}), 201,
            {'Location': user.id})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return render_template('index.php')

# Run the application
if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):

        db.create_all()
    app.run(host='0.0.0.0', port=80, debug=True)
