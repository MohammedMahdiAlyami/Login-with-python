

from flask import Flask, request, jsonify
import re
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from twilio.rest import Client
from dotenv import load_dotenv
from random import randint
import time
from email.message import EmailMessage
import ssl
import smtplib
import sqlite3


load_dotenv()


app = Flask(__name__)
CORS(app, resources={r"*": {"origins": "*"}})

with sqlite3.connect("db.db") as db:
    cursor = db.cursor()

# app.config['MYSQL_HOST'] = 'test8798r4879.mysql.pythonanywhere-services.com'
# app.config['MYSQL_USER'] = 'test8798r4879'
# app.config['MYSQL_PASSWORD'] = 'zjgoinzcehsojwuv'
# app.config['MYSQL_DB'] = 'login'

# conn = psycopg2.connect('postgres://jqhasjqbzazfzo:7d59890842f621c736e1da39e4890992feac9d499b3a1b7853956ceb425ff716@ec2-44-199-22-207.compute-1.amazonaws.com:5432/da5b4nt6udvdqt', sslmode='require')


# mysql = MySQL(app)
# print(mysql)

# cur = db.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS users (id int PRIMARY KEY,
            email text UNIQUE NOT NULL,
            password  text NOT NULL,
            phone text UNIQUE NOT NULL,
            OTP text,
            expiration bigint);'''
            )

db.commit()


TWILIO_ACCOUNT_SID = 'AC82ea4db66ab35d89eb67949b0c392ad3'
TWILIO_AUTH_TOKEN = '8014fb6a9bc40b5515f153cdcfd80804'
twilio_api = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)


@app.get('/')
def hello():
    return "hello"


@app.post('/register')
def register():
    cursor = db.cursor()

    if request.method == 'POST':
        email = request.json['email']
        emailRegex = r'^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-z]+)$'

        if (not (re.search(emailRegex, email))):
            return jsonify({'error': 'Invalid Email'}), 400

        password = request.json['password']
        passwordRegex = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*?[#?!@$%^&*-])(?=.*[a-zA-Z#?!@$%^&*\-\d]).{8,}$'

        if (not (re.search(passwordRegex, password))):
            return jsonify({'error': 'Invalid Password'}), 400

        hashPassword = generate_password_hash(request.json['password'])

        phone = request.json['phone']
        phoneRegex = r'^[+]{1}[9]{1}[6]{2}[0-9]{9}$'

        if (not (re.search(phoneRegex, phone))):
            return jsonify({'error': 'Invalid Phone'}), 400

        sql = 'SELECT * FROM users WHERE phone = ? OR email = ?;'
        params = (phone, email)
        cursor.execute(sql, params)

        users = cursor.fetchall()
        if (len(users) > 0):
            return jsonify({'error': 'Email Or Phone Already Taken'}), 400

        try:
            sql = 'INSERT INTO users(email, password, phone) VALUES ( ?, ?, ?);'
            params = (email, hashPassword, phone)
            cursor.execute(sql, params)

            db.commit()
        except:
            return jsonify({'error': 'Somthing Wrong Happened'}), 500

        return jsonify({'message': 'User registered successfully'}), 201

    return jsonify({'error': 'Bad Request'}), 400


def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)


def expires():
    '''return a UNIX style timestamp representing 5 minutes from now'''
    return int(time.time()+120)


@app.post('/login')
def login():
    cursor = db.cursor()

    if request.method == 'POST':
        email = request.json['email']
        password = request.json['password']
        emailRegex = r'^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-z]+)$'

        if (not (re.search(emailRegex, email))):
            return jsonify({'error': 'Wrong Data'}), 400

        passwordRegex = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*?[#?!@$%^&*-])(?=.*[a-zA-Z#?!@$%^&*\-\d]).{8,}$'

        if (not (re.search(passwordRegex, password))):
            return jsonify({'error': 'Wrong Data'}), 400

        sql = f'SELECT * FROM users WHERE email = ?;'
        cursor.execute(sql, [email])
        user = cursor.fetchone()
        print("user", user)
        if (user):
            if check_password_hash(user[2], password):
                otp = random_with_N_digits(6)
                expire = expires()
                sql = 'UPDATE users SET otp = ? , expiration = ? WHERE email = ?;'
                params = (otp, expire, email)
                cursor.execute(sql, params)
                db.commit()

                emailFrom = 'test8798r4879@gmail.com'
                emailPass = 'zjgoinzcehsojwuv'
                emailTo = user[1]

                subject = 'OTP Verification'
                body = f'Your OTP is {otp}'

                em = EmailMessage()
                em['From'] = emailFrom
                em['To'] = emailTo
                em['Subject'] = subject
                em.set_content(body)
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                    smtp.login(emailFrom, emailPass)
                    smtp.sendmail(emailFrom, emailTo, em.as_string())

                message = twilio_api.messages.create(
                    messaging_service_sid='MG61e07936bcdaaa30425370d6b4aa6c34',
                    to='+966555073533',
                    body=f'Your OTP is {otp}'
                )

                return jsonify({'message': 'Right Data'}), 200

        return jsonify({'error': 'Wrong data'}), 400

    return jsonify({'error': 'Bad Request'}), 400


@app.post('/checkOTP')
def checkOTP():
    cursor = db.cursor()

    if request.method == 'POST':
        email = request.json['email']
        emailRegex = r'^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-z]+)$'

        if (not (re.search(emailRegex, email))):
            return jsonify({'error': 'Wrong Data'}), 400

        otp = request.json['otp']
        now = int(time.time())

        sql = 'SELECT * FROM users WHERE email = ?;'
        params = [email]

        cursor.execute(sql, params)
        user = cursor.fetchone()

        if int(user[4]) == int(otp) and int(user[5]) > now:
            return jsonify({'message': 'Loged Successfully'}), 200

        return jsonify({'error': 'Wrong Or Expired OTP'}), 400

    return jsonify({'error': 'Bad Request'}), 400


@app.post('/resendOTP')
def resendOTP():
    cursor = db.cursor()

    if request.method == 'POST':
        email = request.json['email']

        otp = random_with_N_digits(6)
        expire = expires()
        sql = 'UPDATE users SET otp = ? , expiration = ? WHERE email = ?;'
        params = (otp, expire, email)
        cursor.execute(sql, params)
        db.commit()

        emailFrom = 'test8798r4879@gmail.com'
        emailPass = 'zjgoinzcehsojwuv'
        emailTo = email

        subject = 'OTP Verification'
        body = f'Your OTP is {otp}'

        em = EmailMessage()
        em['From'] = emailFrom
        em['To'] = emailTo
        em['Subject'] = subject
        em.set_content(body)
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(emailFrom, emailPass)
            smtp.sendmail(emailFrom, emailTo, em.as_string())

        message = twilio_api.messages.create(
            messaging_service_sid='MG61e07936bcdaaa30425370d6b4aa6c34',
            to='+966555073533',
            body=f'Your OTP is {otp}'
        )

        return jsonify({'message': 'Resend Successfully'}), 200

    return jsonify({'error': 'Bad Request'}), 400

