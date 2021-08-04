import re
import bcrypt
from flask import Flask, render_template, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import redirect

app = Flask(__name__)
app.secret_key = "my_secret"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///vertical_farming.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)


class ProjectA(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sensorId = db.Column(db.String(100), nullable=False)
    temperature = db.Column(db.String(100))
    moisture = db.Column(db.String(100))
    luminance = db.Column(db.String(100))


class ProjectB(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sensorId = db.Column(db.String(100), nullable=False)
    temperature = db.Column(db.String(100))
    moisture = db.Column(db.String(100))
    luminance = db.Column(db.String(100))


class ProjectC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sensorId = db.Column(db.String(100), nullable=False)
    temperature = db.Column(db.String(100))
    moisture = db.Column(db.String(100))
    luminance = db.Column(db.String(100))


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/admin_page')
def register():
    return render_template('register.html')


@app.route('/welcome')
def welcome():
    if 'user' in session:
        projectA = ProjectA.query.all()
        projectB = ProjectB.query.all()
        projectC = ProjectC.query.all()
        return render_template('welcome.html', projectA=projectA,projectB=projectB,projectC=projectC)
    else:
        return redirect('login')


@app.route('/validate_login', methods=['POST'])
def validate_login():
    userid = request.form.get('userid')
    password = request.form.get('password')

    user = User.query.filter_by(userid=userid).first()
    if bcrypt.checkpw(password.encode('utf-8'), user.password):
        session['user'] = user.userid
        return redirect('/welcome')
    else:
        flash("Wrong credentials!!!")
        return redirect('/login')


@app.route('/validate_register', methods=['POST'])
def validate_register():
    userid = request.form.get('userid')
    password = request.form.get('password')

    validations = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,20}$"
    pat = re.compile(validations)
    mat = re.search(pat, password)

    if mat:
        verify = User.query.filter_by(userid=userid).first()
        if verify:
            flash('User already exist')
            return redirect('/admin_page')
        else:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user = User(userid=userid, password=hashed)
            db.session.add(user)
            db.session.commit()
            return redirect('/admin_page')
    else:
        flash('Please enter a strong password')
        return redirect('/admin_page')


@app.route('/logout')
def logout():
    session.pop('user')
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
