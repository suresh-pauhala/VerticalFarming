import re
import bcrypt
import jwt
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template, request, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import redirect
from functools import wraps

app = Flask(__name__)
app.secret_key = "my_secret"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///vertical_farming.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

token_final = ""
data = ""
project_data = ""


class ProjectNew(db.Model):
    __tablename__ = 'project'
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(100))


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))


class Data(db.Model):
    __tablename__ = 'data'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    sensorId = db.Column(db.String(100), nullable=False)
    property = db.Column(db.String(100))
    value = db.Column(db.String(100))


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = token_final
        if not token:
            return jsonify({'Alert!': 'Token is missing!'}), 401

        try:
            global data
            data = jwt.decode(token, app.secret_key, options={"algorithm": "HS256", "verify_signature": False})
        except:
            return jsonify({'Message': 'Invalid token'}), 403
        return func(*args, **kwargs)

    return decorated


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/admin_page')
def admin():
    return render_template('admin.html')


@app.route('/welcome/<token>')
def welcome(token):
    if 'user' in session:
        return render_template('welcome.html')

    else:
        return redirect('login')


@app.route('/validate_login', methods=['POST'])
def validate_login():
    userid = request.form.get('userid')
    password = request.form.get('password')

    user = User.query.filter_by(userid=userid).first()
    if bcrypt.checkpw(password.encode('utf-8'), user.password):
        session['user'] = user.userid
        token = jwt.encode({
            'user': request.form.get('userid'),
            'project': user.project_id,
            'expiration': str(datetime.utcnow() + timedelta(minutes=60))
        }, app.secret_key)

        global token_final
        token_final = token

        return redirect(url_for('welcome', token=token_final))
    else:
        flash("Wrong credentials!!!")
        return redirect('/login')


@app.route('/validate_register', methods=['POST'])
def validate_register():
    userid = request.form.get('userid')
    password = request.form.get('password')
    project = request.form.get('project')

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
            user = User(userid=userid, password=hashed, project_id=project)
            db.session.add(user)
            db.session.commit()
            return redirect('/admin_page')
    else:
        flash('Please enter a strong password')
        return redirect('/admin_page')


@app.route('/show_project/', methods=['GET'])
@token_required
def show_project():
    project = request.args.get('project')
    print(project)
    token_project = data['project']
    if int(token_project) == int(project):
        if int(project) == 4:
            global project_data
            project_data = Data.query.all()
        else:
            project_data = Data.query.filter_by(project_id=project).all()
    else:
        project_data = None

    return render_template('welcome.html', project_data=project_data)


@app.route('/logout')
def logout():
    session.pop('user')
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
