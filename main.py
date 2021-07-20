import re

from flask import Flask, render_template, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import redirect

app = Flask(__name__)
app.secret_key = "my_secret"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///vertical_farming.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    crop = db.Column(db.String(100), nullable=False)


class CropA(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    temperature = db.Column(db.String(100), nullable=False)
    moisture = db.Column(db.String(100), nullable=False)
    luminance = db.Column(db.String(100), nullable=False)


class CropB(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    temperature = db.Column(db.String(100), nullable=False)
    moisture = db.Column(db.String(100), nullable=False)
    luminance = db.Column(db.String(100), nullable=False)


class CropC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    temperature = db.Column(db.String(100), nullable=False)
    moisture = db.Column(db.String(100), nullable=False)
    luminance = db.Column(db.String(100), nullable=False)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/welcome')
def welcome():
    if 'user' in session:
        return render_template('welcome.html')
    else:
        return redirect('login')


@app.route('/validate_login', methods=['POST'])
def validate_login():
    email = request.form.get('email')
    password = request.form.get('password')
    crop = request.form.get('crops')

    verify = Users.query.filter_by(email=email, password=password, crop=crop).first()
    if verify:
        session['user'] = verify.email
        return redirect('/welcome')
    else:
        flash("Wrong credentials!!!")
        return redirect('/login')


@app.route('/validate_register', methods=['POST'])
def validate_register():
    email = request.form.get('email')
    password = request.form.get('password')
    crop = request.form.get('crops')

    validations = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,20}$"
    pat = re.compile(validations)
    mat = re.search(pat, password)

    if mat:
        verify = Users.query.filter_by(email=email).first()
        if verify:
            flash('User already exist')
            return redirect('/register')
        else:
            user = Users(email=email, password=password, crop=crop)
            db.session.add(user)
            db.session.commit()
            return redirect('/')
    else:
        flash('Please enter a strong password')
        return redirect('/register')


@app.route('/logout')
def logout():
    session.pop('user')
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)


