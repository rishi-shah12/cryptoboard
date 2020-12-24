from flask import Flask,render_template, request, jsonify, make_response, url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager,jwt_required,create_access_token
from flask_mail import Mail, Message
from sqlalchemy import Column, Integer,String, Float, Boolean
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import sendgrid
from sendgrid.helpers.mail import *
import json
import os
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import requests
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY']='secretkey'
basedir = os.path.abspath(os.path.dirname(__file__)) #Where to store the file for the db (same folder as the running application)
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///' + os.path.join(basedir,'users.db') #initalized db
app.config['SECRET_KEY']='secret-key'


SENDGRID_API_KEY = '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'
s = URLSafeTimedSerializer('SECRET_KEY')

sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
db=SQLAlchemy(app)
@app.cli.command('dbCreate')
def db_create():
    db.create_all()
    print('Database created')

@app.cli.command('dbDrop')
def db_drop():
    db.drop_all()
    print('Database Dropped')

@app.cli.command('dbSeed')
def db_seed():
    hashed_password=generate_password_hash('password', method='sha256')
    testUser=User(firstName='Investor',
                    lastName='Investor',
                             email='investor@investor.com',
                             password=hashed_password,
                             confirmedEmail=True,
                             public_id=str(uuid.uuid4()),
                             confirmedOn=None
                             )
    db.session.add(testUser)
    db.session.commit()
    print('Seeded')


class User(db.Model):
    id=Column(Integer, primary_key=True)
    public_id=Column(String(50),unique=True)
    firstName=Column(String(50))
    lastName=Column(String(50))
    email=Column(String(50), unique=True)
    password=Column(String(50))
    confirmedEmail=Column(Boolean)
    confirmedOn=Column(String())


def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-tokens' in request.headers:
            token=request.headers['x-access-tokens']
        if not token:
            return jsonify(message='Token is missing'),401
        try:
            data=jwt.decode(token, app.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify(message='Token is invalid'),401

        return f(current_user, *args, **kwargs)
    return decorated

#User Endpoints
@app.route('/api/login', methods=['POST'])
def login():
    login=request.form
    print(login)

    user=User.query.filter_by(email=login['email']).first()

    if not user:
        return jsonify(message='A user with this email does not exist.')
    if not user.confirmedEmail:
        return jsonify(message='User is not verified')
    if check_password_hash(user.password,login['password']):
        token=jwt.encode({'public_id': user.public_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify(token=token)
    else:
        return jsonify(message='Your email or password is incorrect'),401

@app.route('/api/register', methods=['POST'])
def register():
    data=request.form
    emailUser=data['email']
    print(emailUser)


    test=User.query.filter_by(email=emailUser).first()

    if test:
        return jsonify(message='A user with this email already exists.'), 409
    if data['password'] != data['confirmPassword']:
        return jsonify(message='Passwords do not  match')
    else:
        hashed_password=generate_password_hash(data['password'], method='sha256')
        new_user=User(
                             public_id=str(uuid.uuid4()),
                             firstName=data['firstName'],
                             lastName=data['lastName'],
                             email=data['email'],
                             password=hashed_password,
                             confirmedEmail=False,
                             confirmedOn=None
                             )
        email = data['email']
        from_email = Email("cryptoboard86@gmail.com")
        to_email=To(email)
        subject="Verify your email"
        token = s.dumps(email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)
        content=Content("text/plain", "Your link is {}".format(link))
        mail = Mail(from_email, to_email, subject, content)

        response = sg.client.mail.send.post(request_body=mail.get())
        print(response.status_code)
        print(response.body)
        print(response.headers)
        db.session.add(new_user)
        db.session.commit()
        return jsonify(message='User Created'),201

@app.route('/confirm_email/<token>')
def confirm_email(token):
    return redirect('/auth/' + token)

@app.route('/api/confirm_email/<token>')
def confirm_email_api(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return jsonify(message='token_expired')
    user=User.query.filter_by(email=email).first()
    if user.confirmedEmail:
         return jsonify(message='email_already_confirmed')
    else:
        user.confirmedEmail= True
        user.confirmedOn = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        return jsonify(message='email_confirm_success')

@app.route('/api/register')
def register_page():
    return render_template('register.jinja2')

@app.route('/api/login')
def login_page():
    return render_template('login.jinja2')

@app.route('/')
def landing_page():
    return render_template('landing-page.jinja2')


if __name__ == "__main__":
    app.debug = True
    app.run()
