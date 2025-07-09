import json
from flask import Flask, jsonify, request, g
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)

app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///student_record.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

db = SQLAlchemy(app)

#Models

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    role = db.Column(db.String(20))  # admin, student, teacher
    token = db.Column(db.String(100), unique=True)

class Student(db.Model):
    ID = db.Column(db.Integer, primary_key=True)
    Enroll = db.Column(db.Integer, unique=True, nullable=True)
    Name = db.Column(db.String(256), nullable=True)
    Course = db.Column(db.String(256), nullable=True)
    Result = db.Column(db.Float, nullable=True)

with app.app_context():
    db.create_all()


def auth_required(allowed_roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify(error="Token missing"), 401
            user = User.query.filter_by(token=token).first()
            if not user or user.role not in allowed_roles:
                return jsonify(error="Access denied"), 403
            g.user = user
            return f(*args, **kwargs)
        return decorated
    return wrapper



@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not all(k in data for k in ("username", "password", "role")):
        return jsonify(error="All fields are required"), 400

    if User.query.filter_by(username=data["username"]).first():
        return jsonify(error="Username already exists"), 409

    token = secrets.token_hex(8)
    hashed_password = generate_password_hash(data["password"])

    user = User(
        username=data["username"],
        password=hashed_password,
        role=data["role"],
        token=token
    )
    db.session.add(user)
    db.session.commit()
    return jsonify(msg="User registered", token=token), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data["username"]).first()
    if not user or not check_password_hash(user.password, data["password"]):
        return jsonify(error="Invalid credentials"), 401

    user.token = secrets.token_hex(8)
    db.session.commit()
    return jsonify(token=user.token)

@app.route('/logout', methods=['POST'])
@auth_required(['admin', 'teacher', 'student'])
def logout():
    g.user.token = None
    db.session.commit()
    return jsonify(msg="Logged out successfully")



@app.route('/records', methods=['POST'])
@auth_required(['admin'])
def create_student():
    tb = request.get_json()
    if not all(key in tb for key in ('Name', 'Enroll', 'Course', 'Result')):
        return jsonify(error="All Fields are required!"), 400

    if Student.query.filter_by(Enroll=tb['Enroll']).first():
        return jsonify(msg="Enroll is already registered!")

    new_student = Student(Enroll=tb['Enroll'], Name=tb['Name'], Course=tb['Course'], Result=tb['Result'])
    db.session.add(new_student)
    db.session.commit()
    return jsonify(msg="Student added successfully!"), 201

@app.route('/records', methods=['GET'])
@auth_required(['admin', 'teacher', 'student'])
def get_students():
    students = Student.query.all()
    info = []
    for i in students:
        info.append({
            "ID": i.ID,
            "Enroll": i.Enroll,
            "Name": i.Name,
            "Course": i.Course,
            "Result": i.Result
        })
    return jsonify(info), 200

@app.route('/records/<int:student_id>', methods=['DELETE'])
@auth_required(['admin'])
def delete_student(student_id):
    student = Student.query.get(student_id)
    if student:
        db.session.delete(student)
        db.session.commit()
        return jsonify(msg="Student deleted successfully!")
    return jsonify(error="Student not found!"), 404

@app.route('/records/<int:student_id>', methods=['PATCH'])
@auth_required(['admin', 'teacher'])
def patch_student(student_id):
    student = Student.query.get(student_id)
    if not student:
        return jsonify(error="Student not found!")
    tb = request.get_json()
    if 'Enroll' in tb:
        student.Enroll = tb['Enroll']
    if 'Name' in tb:
        student.Name = tb['Name']
    if 'Course' in tb:
        student.Course = tb['Course']
    if 'Result' in tb:
        student.Result = tb['Result']
    db.session.commit()
    return jsonify(msg="Student updated successfully!"), 200

@app.route('/records/<int:student_id>', methods=['PUT'])
@auth_required(['admin', 'teacher'])
def put_student(student_id):
    student = Student.query.get(student_id)
    if not student:
        return jsonify(error="Student not found!")
    tb = request.get_json()
    student.Enroll = tb['Enroll']
    student.Name = tb['Name']
    student.Course = tb['Course']
    student.Result = tb['Result']
    db.session.commit()
    return jsonify(msg="Student updated successfully!"), 200

@app.route('/result/<int:student_id>', methods=['GET'])
@auth_required(['student'])
def get_result(student_id):
    student = Student.query.get(student_id)
    if not student:
        return jsonify(error="Student not found!")
    return jsonify(Name=student.Name, Result=student.Result), 200


if __name__ == '__main__':
    app.run(debug=True)