import flask
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
import addon
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import requests
from functools import wraps
from flask import Flask, session
import cryptocompare

app = Flask(__name__)

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

class Portfolio(db.Model):
    id=Column(Integer,primary_key=True)
    user_id=Column(String(50))
    portfolio_id=Column(String(50),unique=True)
    portfolioName=Column(String(50))
    dateCreated=Column(String())
    marketValue=Column(Float)
    currency=Column(String())
    institution=Column(String())
    cash=Column(Float)

class Transcation(db.Model):
    id=Column(Integer,primary_key=True)
    user_id=Column(String(50))
    portfolio_id=Column(String(50))
    transcation_id=Column(String(50),unique=True)
    date=Column(String())
    typeCurr=Column(String())
    Curr=Column(String())
    typeTrans=Column(String())
    priceofCryptoATTrans=Column(Float)
    quantityTrans=Column(Float)
    TranscationValue=Column(Float)


def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        if 'token' not in session:
            return render_template('need-to-login-error.jinja2')
        else:
            if session is None:
                return render_template('need-to-login-error.jinja2')
            if 'cookie' in request.headers:
                token=session['token']
            if 'cookie' not in request.headers:
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

    user=User.query.filter_by(email=login['email']).first() #Qeuried id=email

    if not user:
        return jsonify(message='A user with this email does not exist.')
    if not check_password_hash(user.password,login['password']):
        return jsonify(message='Incorrect Password')
    if not user.confirmedEmail:
        return render_template('verify-email.jinja2')
    if check_password_hash(user.password,login['password']): #queried password
        token=jwt.encode({'public_id': user.public_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        session['token'] = token
        redir = redirect(url_for('user'))
        redir.headers['x-access-tokens'] = token
        return redir
    else:
        return jsonify(message='Your email or password is incorrect'),401

@app.route('/api/register', methods=['POST'])
def register():
    data=request.form
    emailUser=data['email']
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


@app.route('/api/user', methods=['GET'])
@token_required
def user(current_user):
    user_data={}
    user_data['firstName']=current_user.firstName
    user_data['lastName']=current_user.lastName
    user_data['email']=current_user.email
    user_data['confirmedEmail']=current_user.confirmedEmail
    user_data['confirmedOn']=current_user.confirmedOn


    return render_template('logged-in-landing-page.jinja2', userdata=user_data)
@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return render_template('email-redirect.jinja2', message='Token Expired',
                               subtitle="You'll need to request a new email", link="{{ url_for(new_email) }}", name="Send Email Again")
    user=User.query.filter_by(email=email).first()
    if user.confirmedEmail:
        return render_template('email-redirect.jinja2', message='Email Already Verified',
                               subtitle="You have already verified you email", link="{{ url_for(landing_page) }}", name="Back to Home")
    else:
        user.confirmedEmail= True
        user.confirmedOn = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        return render_template('email-redirect.jinja2', message='Email Successfully Verified',
                               subtitle="You can now experience Cryptoboard", link="{{ url_for(landing_page) }}", name="Back to Home")

@app.route('/api/portfolio', methods=['POST'])
@token_required
def portfolioCreate(current_user):
    user_data={}
    user_data['public_id']=current_user.public_id

    portfolio=request.form
    userPort=Portfolio.query.filter_by(user_id=user_data['public_id'], portfolioName=portfolio['portfolioName']).first()
    if userPort:
        return jsonify(message="Portfolio with the same name exists"),401
    else:
        newPortfolio=Portfolio(
                user_id=user_data['public_id'],
                portfolio_id=str(uuid.uuid4()),
                portfolioName=portfolio['portfolioName'],
                dateCreated=datetime.datetime.now(),
                marketValue=portfolio['marketValue'],
                cash=portfolio['cash'],
                currency=portfolio['currency'],
                institution=portfolio['institution']

        )
        db.session.add(newPortfolio)
        db.session.commit()
        return jsonify(message="Portfolio Created"),201

@app.route('/api/portfolio', methods=['GET'])
@token_required
def portfolioView(current_user):
    user={}
    user['public_id']=current_user.public_id
    userPort=Portfolio.query.filter_by(user_id=user['public_id']).all()
    output=[]
    if userPort:
        for port in userPort:
            portfolio={}
            portfolio['portfolioName']=port.portfolioName
            portfolio['marketValue'] =port.marketValue
            portfolio['dateCreated'] =port.dateCreated
            portfolio['portfolio_id']=port.portfolio_id
            portfolio['cash']=port.cash
            portfolio['currency']=port.currency
            portfolio['institution']=port.institution
            output.append(portfolio)
        return jsonify(userPortfolios=output)
    else:
        return jsonify(message="No portfolios")

@app.route('/api/portfolioNames', methods=['GET'])
@token_required
def portfolioViewNames(current_user):
    user={}
    user['public_id']=current_user.public_id
    userPort=Portfolio.query.filter_by(user_id=user['public_id']).all()
    output=[]
    if userPort:
        for port in userPort:
            portfolio={}
            portfolio['portfolioName']=port.portfolioName
            output.append(portfolio)
        return jsonify(userPortfolios=output)
    else:
        return jsonify(message="No portfolios")

@app.route('/api/portfolio/<portfolio_id>', methods=['GET'])
@token_required
def viewPortfolio(current_user,portfolio_id):
    user={}
    user['public_id']=current_user.public_id
    userPort=Portfolio.query.filter_by(user_id=user['public_id'], portfolio_id=portfolio_id).first()

    if userPort:
        portfolio={}
        portfolio['portfolioName']=userPort.portfolioName
        portfolio['marketValue'] =userPort.marketValue
        portfolio['dateCreated'] =userPort.dateCreated
        portfolio['cash']=userPort.cash
        portfolio['currency']=userPort.currency
        portfolio['institution']=userPort.institution

        return jsonify(portfolio=portfolio)
    else:
        return jsonify(message="Could not find portfolio")
@app.route('/api/portfolio/<portfolio_id>', methods=['DELETE'])
@token_required
def deletePortfolio(current_user, portfolio_id):
    user={}
    user['public_id']=current_user.public_id
    userPort=Portfolio.query.filter_by(user_id=user['public_id'], portfolio_id=portfolio_id).first()

    if userPort:
        db.session.delete(userPort)
        db.session.commit()
        return jsonify(message="Portfolio Closed")
    else:
        return jsonify(message="Portfolio does not exist")
@app.route('/api/refund/<portfolio_id>/<transcation_id>', methods=['DELETE'])
@token_required
def refund(current_user, portfolio_id,transcation_id):

    user={}
    user['public_id']=current_user.public_id
    userTrans=Transcation.query.filter_by(user_id=user['public_id'], portfolio_id=portfolio_id, transcation_id=transcation_id).first()
    userPort=Portfolio.query.filter_by(user_id=user['public_id'], portfolio_id=portfolio_id).first()
    if userPort:
        if userTrans:
            user_Trans={}
            user_Trans['typeTrans']=userTrans.typeTrans
            user_Trans['TranscationValue']=userTrans.TranscationValue  
            user_Trans['cash']=userPort.cash
        else:
            return jsonify(message="Transaction not found")
    else:
        return jsonify(message="Portfolio not found")

    if user_trans['typeTrans']=="BUY":
        userPort.cash=float(user_Trans['cash']+user_Trans['TranscationValue'])
    else:
        userPort.cash=float(user_Trans['cash']-user_Trans['TranscationValue'])

    db.session.delete(userTrans)
    db.session.commit()
    return jsonify(message="Transcartion has been refunded")




@app.route('/api/cryptoTransaction/<portfolio_id>', methods=['POST'])
@token_required
def buyCrypto (current_user, portfolio_id):
    trans=request.form
   
    
    user={}
    user['public_id']=current_user.public_id
    userPort=Portfolio.query.filter_by(user_id=user['public_id'], portfolio_id=portfolio_id).first()
    if userPort:
        portfolio={}
        portfolio['curr']=userPort.currency
        currency=str(portfolio['curr'])

    units=float(trans['quantityTrans'])
    name=str(trans['curr'])   
    priceperunit=float(cryptocompare.get_historical_price_hour(name,curr=currency)[0]['close'])
    transactionValue=round(units*priceperunit,2)
    if userPort:
        portfolio={}
        portfolio['cash']=userPort.cash
        cash=float(portfolio['cash'])
    if userPort:
        if cash >=transactionValue:
            newTrans=Transcation(
                user_id=user['public_id'],
                portfolio_id=portfolio_id,
                transcation_id=str(uuid.uuid4()),
                date=datetime.datetime.now(),
                typeCurr="CRYPTO",
                Curr=trans['curr'],
                typeTrans="BUY",
                priceofCryptoATTrans=priceperunit,
                quantityTrans=trans['quantityTrans'],
                TranscationValue= transactionValue
            )
            userPort.cash=cash-transactionValue
            db.session.add(newTrans)
            db.session.commit()
            return jsonify(message="Successful Transcation")
        else:
            return jsonify(message="You do not have the necessary funds")
    else:
        return jsonify(message="Portfolio not found")

@app.route('/api/cryptoSell/<portfolio_id>', methods=['POST'])
@token_required
def sellCrypto (current_user, portfolio_id):
    trans=request.form
    user={}
    user['public_id']=current_user.public_id
    userPort=Portfolio.query.filter_by(user_id=user['public_id'], portfolio_id=portfolio_id).first()
    if userPort:
        portfolio={}
        portfolio['curr']=userPort.currency
        currency=str(portfolio['curr'])

    units=float(trans['quantityTrans'])
    name=str(trans['curr'])   
    priceperunit=float(cryptocompare.get_historical_price_hour(name,curr=currency)[0]['close'])
    transactionValue=round(units*priceperunit,2)
    if userPort:
        portfolio={}
        portfolio['cash']=userPort.cash
        cash=float(portfolio['cash'])
    if userPort:
        
        newTrans=Transcation(
                user_id=user['public_id'],
                portfolio_id=portfolio_id,
                transcation_id=str(uuid.uuid4()),
                date=datetime.datetime.now(),
                typeCurr="CRYPTO",
                Curr=trans['curr'],
                typeTrans="SELL",
                priceofCryptoATTrans=priceperunit,
                quantityTrans=trans['quantityTrans'],
                TranscationValue= transactionValue
            )
        userPort.cash=cash+transactionValue
        db.session.add(newTrans)
        db.session.commit()
        return jsonify(message="Successful Transcation")
        
    else:
        return jsonify(message="Portfolio not found")

@app.route('/api/deposit/<portfolio_id>', methods=['POST'])
@token_required
def depositCash (current_user, portfolio_id):
    user={}
    user['public_id']=current_user.public_id
    userPort=Portfolio.query.filter_by(user_id=user['public_id'], portfolio_id=portfolio_id).first()
    trans=request.form
    if userPort:
        portfolio={}
        portfolio['cash']=userPort.cash
        cash=float(portfolio['cash'])
    if userPort:
        newTrans=Transcation(
                user_id=user['public_id'],
                portfolio_id=portfolio_id,
                transcation_id=str(uuid.uuid4()),
                date=datetime.datetime.now(),
                typeCurr="CASH",
                Curr=userPort.currency,
                typeTrans="DEPOSIT",
                priceofCryptoATTrans=0,
                quantityTrans=0,
                TranscationValue=trans['cash']
            )
        userPort.cash=cash+float(trans['cash'])
        db.session.add(newTrans)
        db.session.commit()
        return jsonify(message="Successful Transcation")
        
    else:
        return jsonify(message="Portfolio not found")

@app.route('/api/withdrawl/<portfolio_id>', methods=['POST'])
@token_required
def withdrawlCash (current_user, portfolio_id):
    user={}
    user['public_id']=current_user.public_id
    userPort=Portfolio.query.filter_by(user_id=user['public_id'], portfolio_id=portfolio_id).first()
    trans=request.form
    withdrawl=float(trans['cash'])
    if userPort:
        portfolio={}
        portfolio['cash']=userPort.cash
        cash=float(portfolio['cash'])
    if userPort:
        if cash >=withdrawl:
            newTrans=Transcation(
                    user_id=user['public_id'],
                    portfolio_id=portfolio_id,
                    transcation_id=str(uuid.uuid4()),
                    date=datetime.datetime.now(),
                    typeCurr="CASH",
                    Curr=userPort.currency,
                    typeTrans="WITHDRAWL",
                    priceofCryptoATTrans=0,
                    quantityTrans=0,
                    TranscationValue=trans['cash']
                )
            userPort.cash=cash-withdrawl
            db.session.add(newTrans)
            db.session.commit()
            return jsonify(message="Successful Transcation")
        else:
            return jsonify(message="You do not have the funds")
        
    else:
        return jsonify(message="Portfolio not found")

@app.route('/api/getTransaction/<portfolio_id>', methods=['GET'])
@token_required
def transcations (current_user, portfolio_id):
    user={}
    user['public_id']=current_user.public_id
    userTrans=Transcation.query.filter_by(user_id=user['public_id'], portfolio_id=portfolio_id).all()
    UserTrans=[]
    if userTrans:
        for Trans in userTrans:
            user_Trans={}
            user_Trans['transcation_id']=Trans.transcation_id
            user_Trans['date']=Trans.date
            user_Trans['typeCurr']=Trans.typeCurr
            user_Trans['Curr']=Trans.Curr
            user_Trans['typeTrans']=Trans.typeTrans
            user_Trans['priceofCryptoATTrans']=Trans.priceofCryptoATTrans
            user_Trans['quantityTrans']=Trans.quantityTrans
            user_Trans['TranscationValue']=Trans.TranscationValue
            UserTrans.append(user_Trans)
    else:
        return jsonify(message="No Transcations")

    userPort=Portfolio.query.filter_by(user_id=user['public_id'], portfolio_id=portfolio_id).first()
    
    if userPort:
        portfolio={}
        portfolio['curr']=userPort.currency
        currency=str(portfolio['curr'])
   
    priceBTC=float(cryptocompare.get_historical_price_hour('BTC',curr=currency)[0]['close'])
    priceETH=float(cryptocompare.get_historical_price_hour('ETH',curr=currency)[0]['close'])
    ethQuantity=0
    btcQuantity=0
    ethInvested=0
    btcInvested=0
    for trans in UserTrans:
        if str(trans['typeCurr'])=="CRYPTO":
            if str(trans['Curr'])=="ETH":
                if str(trans['typeTrans'])=="BUY":
                    ethQuantity+=float(trans['quantityTrans'])
                    ethInvested+=float(trans['TranscationValue'])
                else:
                    ethQuantity+=-float(trans['quantityTrans'])
                        
            elif str(trans['Curr'])=="BTC":
                    if str(trans['typeTrans'])=="BUY":
                        btcQuantity+=float(trans['quantityTrans'])
                        btcInvested+=float(trans['TranscationValue'])
                    else:
                        btcQuantity+=-float(trans['quantityTrans'])
    ethValue=ethQuantity*priceETH
    btcValue=btcQuantity*priceBTC
    gainETH=ethValue-ethInvested
    gainBTC=btcValue-btcInvested
    gainBTCper=0.0
    gainETHper=0.0
    if ethInvested==0.0:
        gainETHper=0.0
    elif btcInvested==0:
        gainBTCper=0.0
    elif btcInvested!=0:
        gainBTCper=(gainBTC/btcInvested)*100
    elif ethInvested!=0:
        gainETHper=(gainETH/ethInvested)*100
   

    portfolioCrypto={}
    portfolioCrypto['BTCQuantity']=btcQuantity
    portfolioCrypto['ETHQuantity']=ethQuantity
    portfolioCrypto['ETHValue']=ethValue
    portfolioCrypto['BTCValue']=btcValue
    portfolioCrypto['marketValue']=btcValue+ethValue
    portfolioCrypto['gainETH']=gainETH
    portfolioCrypto['gainETHper']=gainETHper
    portfolioCrypto['gainBTC']=gainBTC
    portfolioCrypto['gainBTCper']=gainBTCper

    allData=[]
    allData.append(portfolioCrypto)

    values=[allData,UserTrans]
    return jsonify(message=values)


@app.route('/api/logout')
def logout_page():
    session.pop('token', None)
    return render_template('signed-out.jinja2')


@app.route('/api/register')
def register_page():
    return render_template('register.jinja2')

@app.route('/api/login')
def login_page():
    return render_template('login.jinja2')


@app.route('/home/logged-in')
def logged_in_landing_page():
    return render_template('logged-in.jinja2')

@app.route('/')
def landing_page():
    return render_template('landing-page.jinja2')

if __name__ == "__main__":
    app.debug = True
    app.run()
