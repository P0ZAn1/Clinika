import os
from sqlite3 import IntegrityError

from flask import Flask, render_template, url_for, redirect, make_response
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, set_access_cookies, unset_jwt_cookies, get_jwt_identity
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
import sqlite3
from flask import request
from flask_bcrypt import Bcrypt

app = Flask(__name__)
secret_key = os.urandom(24)
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_super_secret_jwt_key'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = True #False  # Установите в True на production
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/refresh'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False #True  # Включите CSRF защиту
app.config['JWT_ALGORITHM'] = 'HS256'
jwt = JWTManager(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# Функция для получения соединения с базой данных
def get_db_connection(database):
    conn = sqlite3.connect(database)
    return conn

# Функция для шифрования данных с помощью XOR
def xor_encrypt(data, key):
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key * len(data)))


# Функция для создания таблицы Врачи
def create_doctors_table():
    conn = get_db_connection('blog.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS doctors
                 (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, password TEXT NOT NULL, speciality VARCHAR(60) NOT NULL, experience INT NOT NULL, photo_doctor TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'Доктор')''')
    conn.commit()
    conn.close()

def get_patients_by_doctor_id(doctor_id):
    conn = get_db_connection('blog.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users_identification WHERE id_doctor=?', (doctor_id,))
    patients = c.fetchall()
    conn.close()
    return patients


# Функция для создания таблицы пользователей
def create_users_identification_table():
    conn = get_db_connection('blog.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users_identification
                 (id INTEGER PRIMARY KEY,id_doctor INT, name VARCHAR(80) UNIQUE NOT NULL, gender TEXT, location TEXT, diagnoze TEXT,
                 phone_numbers INTEGER UNIQUE NOT NULL, pasport INTEGER UNIQUE NOT NULL, snils INTEGER UNIQUE NOT NULL, age INTEGER,FOREIGN KEY(id_doctor) REFERENCES doctor(id));''')
    conn.commit()
    conn.close()
    #print("Таблица 'users_identification' создана успешно.")

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    gender = db.Column(db.String(20))
    location = db.Column(db.String(100))
    diagnoze = db.Column(db.String(200))
    phone_numbers = db.Column(db.String, unique=True)
    passport = db.Column(db.String, unique=True)
    snils = db.Column(db.String, unique=True)
    age = db.Column(db.String)

    def __init__(self, id, name, gender, location, diagnoze, phone_numbers, passport, snils, age):
        self.id = id
        self.name = name
        self.gender = gender
        self.location = location
        self.diagnoze = diagnoze
        self.phone_numbers = phone_numbers
        self.passport = passport
        self.snils = snils
        self.age = age

# Модель данных для врачей
class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    speciality = db.Column(db.String(200))
    experience = db.Column(db.Integer)
    photo_doctor = db.Column(db.String)
    role = db.Column(db.String(20))

@app.route('/')
@app.route('/Вход', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        # Шифруем пароль с помощью XOR
        password_hashed = xor_encrypt(password, 'your_secret_key')

        # Проверяем логин и пароль в базе данных
        conn = sqlite3.connect('blog.db')
        cursor = conn.cursor()
        doctor = cursor.execute("SELECT * FROM doctors WHERE name=? AND password=?", (login, password_hashed)).fetchone()
        conn.close()

        if doctor:
            if doctor[6] == 'Доктор':
                access_token = create_access_token(identity=doctor[0], expires_delta=timedelta(hours=1))
                response = make_response(redirect(url_for('profile', doctor_id=doctor[0])))
                set_access_cookies(response, access_token)
                return response
            else:
                access_token = create_access_token(identity=doctor[0], expires_delta=timedelta(hours=1))
                response = make_response(redirect(url_for('add_doctor')))
                set_access_cookies(response, access_token)
                return response
        else:
            return render_template('Вход.html', error='Неверный логин или пароль')

    return render_template('Вход.html')


@app.route('/exit')
def exit():
    response = make_response(redirect(url_for('index')))
    unset_jwt_cookies(response)
    return response


@app.route('/Главная', methods=['GET', 'POST'])
@jwt_required()
def xyq():
    error_message = None
    form_data = {}

    if request.method == 'POST':
        form_data = request.form.to_dict()
        try:
            # Получаем данные пациента из формы
            name = form_data['name']
            gender = form_data['gender']
            location = form_data['location']
            diagnoze = form_data['diagnoze']
            phone_numbers = form_data['phone_numbers']
            pasport = form_data['pasport']
            snils = form_data['snils']
            age = form_data['age']

            # Получаем имя врача из сессии
            doctor_id = get_jwt_identity()

            # Шифруем данные с помощью XOR
            phone_numbers_hashed = xor_encrypt(str(phone_numbers), 'key1')
            pasport_hashed = xor_encrypt(str(pasport), 'key2')
            snils_hashed = xor_encrypt(str(snils), 'key3')
            age_hashed = xor_encrypt(str(age), 'key4')

            phone_numbers = phone_numbers_hashed
            pasport = pasport_hashed
            snils = snils_hashed
            age = age_hashed

            # Добавляем данные в базу данных
            with get_db_connection('blog.db') as conn:
                c = conn.cursor()
                c.execute(
                    "INSERT INTO users_identification (name, gender, location, diagnoze, phone_numbers, pasport, snils, age, id_doctor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (name, gender, location, diagnoze, phone_numbers, pasport, snils, age, doctor_id))
                conn.commit()
                form_data = {}
        except IntegrityError as e:
            if 'UNIQUE constraint failed' in str(e):
                if 'users_identification.phone_numbers' in str(e):
                    error_message = "Ошибка: Этот номер телефона уже зарегистрирован."
                elif 'users_identification.pasport' in str(e):
                    error_message = "Ошибка: Эти паспортные данные уже зарегистрированы."
                elif 'users_identification.snils' in str(e):
                    error_message = "Ошибка: Этот СНИЛС уже зарегистрирован."
            else:
                error_message = "Произошла ошибка при добавлении пациента."

    # Получаем имя врача из сессии
    doctor_id = get_jwt_identity()

    with get_db_connection('blog.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users_identification WHERE id_doctor=?', (doctor_id,))
        patients = [Patient(row[0], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9]) for row in
                    c.fetchall()]

    for patient in patients:
        print(patient)

    with get_db_connection('blog.db') as conn:
        c = conn.cursor()
        c.execute('SELECT name FROM doctors WHERE id=?', (doctor_id,))
        doctor_name = c.fetchone()[0]

    return render_template('Главная.html', data=patients, doctor_name=doctor_name, doctor_id=doctor_id,
                           error=error_message, form_data=form_data)


@app.route('/add_doctor', methods=['GET', 'POST'])
@jwt_required()
def add_doctor():
    # Получаем идентификатор текущего пользователя из JWT
    current_user_id = get_jwt_identity()

    # Проверяем, является ли пользователь администратором
    conn = get_db_connection('blog.db')
    c = conn.cursor()
    c.execute('SELECT * FROM doctors WHERE role="Доктор"')
    doctors = c.fetchall()
    c.execute('SELECT role FROM doctors WHERE id=?', (current_user_id,))
    user_role = c.fetchone()[0]
    conn.close()

    if user_role != 'root':
        return 'Вы не имеете доступа к этой странице', 403

    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        password_hashed = xor_encrypt(password, 'your_secret_key')
        speciality = request.form['speciality']
        experience = request.form['experience']
        photo_doctor = request.form['photo_doctor']

        conn = get_db_connection('blog.db')
        c = conn.cursor()
        c.execute("INSERT INTO doctors (name, password, speciality, experience, photo_doctor) VALUES (?, ?, ?, ?, ?)", (name, password_hashed, speciality, experience, photo_doctor))
        conn.commit()
        conn.close()

        return redirect(url_for('add_doctor'))

    conn.close()
    return render_template('add_doctor.html', doctors=doctors)


@app.route('/edit/<int:patient_id>', methods=['GET', 'POST'])
@jwt_required()
def edit_patient(patient_id):
    if request.method == 'POST':
        # Получаем обновленные данные пациента из формы
        name = request.form['name']
        gender = request.form['gender']
        location = request.form['location']
        diagnoze = request.form['diagnoze']
        phone_numbers = request.form['phone_numbers']
        pasport = request.form['pasport']
        snils = request.form['snils']
        age = request.form['age']

        # Шифруем данные с помощью XOR
        phone_numbers_hashed = xor_encrypt(str(phone_numbers), 'key1')
        pasport_hashed = xor_encrypt(str(pasport), 'key2')
        snils_hashed = xor_encrypt(str(snils), 'key3')
        age_hashed = xor_encrypt(str(age), 'key4')

        # Обновляем данные пациента в базе данных
        conn = get_db_connection('blog.db')
        c = conn.cursor()
        c.execute("UPDATE users_identification SET name=?, gender=?, location=?, diagnoze=?, phone_numbers=?, pasport=?, snils=?, age=? WHERE id=?",
                  (name, gender, location, diagnoze, phone_numbers_hashed, pasport_hashed, snils_hashed, age_hashed, patient_id))
        conn.commit()
        conn.close()

        return redirect(url_for('main'))

    with get_db_connection('blog.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users_identification WHERE id=?', (patient_id,))
        patient = c.fetchone()

    if patient:
        return render_template('Редактирование.html',
                               patient={
                                   'id': patient[0],
                                   'name': patient[2],
                                   'gender': patient[3],
                                   'location': patient[4],
                                   'diagnoze': patient[5],
                                   'phone_numbers': xor_encrypt(patient[6], 'key1'),
                                   'pasport': xor_encrypt(patient[7], 'key2'),
                                   'snils': xor_encrypt(patient[8], 'key3'),
                                   'age': xor_encrypt(patient[9], 'key4')
                               })
    else:
        return 'Пациент не найден', 404


@app.route('/delete_doctor/<int:doctor_id>', methods=['GET','POST'])
@jwt_required()
def delete_doctor(doctor_id):
    # Проверяем, является ли пользователь администратором
    current_user_id = get_jwt_identity()
    conn = get_db_connection('blog.db')
    c = conn.cursor()
    c.execute('SELECT role FROM doctors WHERE id=?', (current_user_id,))
    user_role = c.fetchone()[0]
    conn.close()

    if user_role != 'root':
        return 'Вы не имеете доступа к этой странице', 403

    # Удаляем врача из базы данных
    conn = get_db_connection('blog.db')
    c = conn.cursor()
    c.execute("DELETE FROM doctors WHERE id=?", (doctor_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('add_doctor'))


@app.route('/delete/<int:patient_id>', methods=['POST'])
@jwt_required()
def delete_patient(patient_id):
    conn = get_db_connection('blog.db')
    c = conn.cursor()
    c.execute("DELETE FROM users_identification WHERE id=?", (patient_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('index'))


@app.route('/changeinfo', methods=['POST'])
@jwt_required()
def changeinfo():
    id = request.form['id']
    name = request.form['name']
    gender = request.form['gender']
    location = request.form['location']
    diagnoze = request.form['diagnoze']
    phone_numbers = request.form['phone_numbers']
    pasport = request.form['pasport']
    snils = request.form['snils']
    age = request.form['age']

    # Шифруем данные с помощью XOR
    phone_numbers_hashed = xor_encrypt(str(phone_numbers), 'key1')
    pasport_hashed = xor_encrypt(str(pasport), 'key2')
    snils_hashed = xor_encrypt(str(snils), 'key3')
    age_hashed = xor_encrypt(str(age), 'key4')

    conn = get_db_connection('blog.db')
    c = conn.cursor()
    c.execute(
        "UPDATE users_identification SET name=?, gender=?, location=?, diagnoze=?, phone_numbers=?, pasport=?, snils=?, age=? WHERE id=?",
        (name, gender, location, diagnoze, phone_numbers_hashed, pasport_hashed, snils_hashed, age_hashed, id))
    conn.commit()
    conn.close()

    return redirect(url_for('xyq'))


@app.route('/Профиль/<int:doctor_id>', methods=['GET', 'POST'])
@jwt_required()
def profile(doctor_id):
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        speciality = request.form['speciality']
        experience = request.form['experience']

        conn = get_db_connection('blog.db')
        c = conn.cursor()
        c.execute("UPDATE doctors SET name=?, password=?, speciality=?, experience=? WHERE id=?",
                  (name, password, speciality, experience, doctor_id))
        conn.commit()
        conn.close()

        return redirect(url_for('profile', doctor_id=doctor_id))

    # Получаем данные врача из базы данных
    conn = get_db_connection('blog.db')
    c = conn.cursor()
    c.execute('SELECT * FROM doctors WHERE id=?', (doctor_id,))
    doctor = c.fetchone()
    conn.close()

    if doctor:
        patients = get_patients_by_doctor_id(doctor_id)
        return render_template('Профиль.html',
                               doctor={
                                   'id': doctor[0],
                                   'name': doctor[1],
                                   'password': doctor[2],
                                   'speciality': doctor[3],
                                   'experience': doctor[4],
                                   'photo_doctor': doctor[5]
                               },
                               patient_count=len(patients))
    else:
        return 'Врач не найден'


#смена пароля врача
@app.route('/change_password/<int:doctor_id>', methods=['GET', 'POST'])
@jwt_required()
def change_password(doctor_id):
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Шифруем пароли с помощью XOR
        current_password_hashed = xor_encrypt(current_password, 'your_secret_key')
        new_password_hashed = xor_encrypt(new_password, 'your_secret_key')

        # Проверяем, что новый пароль и подтверждение совпадают
        if new_password_hashed != xor_encrypt(confirm_password, 'your_secret_key'):
            return render_template('change_password.html', error='Новый пароль и подтверждение не совпадают')

        # Получаем врача из базы данных
        conn = get_db_connection('blog.db')
        c = conn.cursor()
        c.execute('SELECT * FROM doctors WHERE id=?', (doctor_id,))
        doctor = c.fetchone()
        conn.close()

        # Проверяем, что текущий пароль правильный
        if doctor[2] != current_password_hashed:
            return render_template('change_password.html', error='Неверный текущий пароль')

        # Обновляем пароль врача в базе данных
        conn = get_db_connection('blog.db')
        c = conn.cursor()
        c.execute("UPDATE doctors SET password=? WHERE id=?", (new_password_hashed, doctor_id))
        conn.commit()
        conn.close()

        return redirect(url_for('profile', doctor_id=doctor_id))

    return render_template('change_password.html')


@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('index')))
    unset_jwt_cookies(response)
    return response


@app.route('/реклама')
def reclama():
    return render_template('реклама.html')


if __name__ == '__main__':
    create_doctors_table()
    create_users_identification_table()
    app.run(debug=True)
