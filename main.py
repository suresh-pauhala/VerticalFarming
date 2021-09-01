import re
import bcrypt
import jwt
import time
import random
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template, request, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import redirect
from functools import wraps
import paho.mqtt.client as mqtt
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "my_secret"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///vertical_farming.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

token_final = ""
data = ""
project_data = ""

Connected = False

broker_address = "127.0.0.1"
port = 1883
user = ""
password = ""


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
    sensorId = db.Column(db.String(100), db.ForeignKey('sensor.name'))
    property = db.Column(db.String(100))
    time_stamp = db.Column(db.DateTime)
    value = db.Column(db.String(100))


class Sensor(db.Model):
    __tablename__ = 'sensor'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    status = db.Column(db.Integer)
    battery_level_percentage = db.Column(db.Integer)
    location = db.Column(db.String(100))
    threshold = db.Column(db.Integer)
    model = db.Column(db.String(100))
    software_version = db.Column(db.String(100))



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


@app.route('/device')
def device():
    return render_template('device.html')


@app.route('/welcome/<token>')
def welcome(token):
    if 'user' in session:
        connect()
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


@app.route('/validate_sensor_register', methods=['POST'])
def validate_sensor_register():
    name = request.form.get('name')
    model = request.form.get('model')
    version = request.form.get('version')
    threshold = request.form.get('threshold')
    location = request.form.get('location')

    sensor_register = Sensor(name=name, status="ON", battery_level_percentage=95, model=model, software_version=version, threshold=threshold, location=location)
    db.session.add(sensor_register)
    db.session.commit()
    return redirect('/device')


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

    return render_template('welcome.html', project_data=project_data,project=project)

@app.route('/project_sensors/', methods=['GET'])
@token_required
def project_sensors():
    sensor = request.args.get('sensor')

    sensor_info = Sensor.query.filter_by(name=sensor).all()
    sensor_data = Data.query.filter_by(sensorId=sensor)
    last_day = datetime.utcnow() - timedelta(days=1)
    print(last_day)
    last_24_hours_data = Data.query.filter(Data.time_stamp > last_day).filter(Data.time_stamp < datetime.utcnow()).filter(Data.sensorId==sensor).all()
    labels = [row.time_stamp for row in last_24_hours_data]
    values = [row.value for row in last_24_hours_data]

    return render_template('sensor.html', sensor_info=sensor_info,sensor_data=sensor_data,labels=labels, values=values, last_24_hours_data=last_24_hours_data)

@app.route('/logout')
def logout():
    session.pop('user')
    return redirect('/login')


def on_connect(client, userdata, flags, rc):
    if rc == 0:

        print("Connected to broker")

        global Connected
        Connected = True

    else:
        print("Connection failed")


def on_message(client, userdata, message):
    msg = str(message.payload.decode("utf-8", "ignore"))
    data_value = int(msg)
    current_time = datetime.utcnow()
    print("Message received: " + msg)
    project_select = random.randrange(1, 4)
    SensorId_rand = random.randrange(1, 3)
    sensorId_char_rand = 1
    project_id = project_select

    if (project_id == 1):
        sensorId_char_rand = 65
    elif(project_id == 2):
        sensorId_char_rand = 66
    elif (project_id == 3):
        sensorId_char_rand = 67

    s_Id_char = chr(sensorId_char_rand)
    if 20 < data_value < 45:
        sensorId="Temp"
        sensorId = sensorId+s_Id_char+str(SensorId_rand)


        temp = Data(project_id=project_id, sensorId=sensorId, property="Temperature", time_stamp=current_time, value=data_value)
        db.session.add(temp)
        db.session.commit()
    elif 50 < data_value < 100:
        sensorId = "Moist"
        sensorId = sensorId + s_Id_char + str(SensorId_rand)
        moist = Data(project_id=project_id, sensorId=sensorId, property="Moisture", time_stamp=current_time, value=data_value)
        db.session.add(moist)
        db.session.commit()
    elif 200 < data_value < 500:
        sensorId = "Lum"
        sensorId = sensorId + s_Id_char + str(SensorId_rand)
        lum = Data(project_id=project_id, sensorId=sensorId, property="Luminance", time_stamp=current_time, value=data_value)
        db.session.add(lum)
        db.session.commit()





def connect():
    broker_address = "127.0.0.1"
    port = 1883
    user = "projects"
    password = "Vfarm@123"

    client = mqtt.Client("VFarm")
    client.username_pw_set(user, password=password)
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(broker_address, port=port)

    client.loop_start()

    while not Connected:
        time.sleep(0.1)

    client.subscribe("sensors/testclient")
    return render_template('welcome.html')


if __name__ == '__main__':
    app.run(debug=True)
