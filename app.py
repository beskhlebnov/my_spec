import json
from typing import List, Dict
from flask import Flask, request, jsonify
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import jwt
import sqlite3
from functools import wraps
import bcrypt
from flask_cors import CORS
from scipy import stats

app = Flask(__name__)
CORS(app)

debugMail = True

app.config['SECRET_KEY'] = ''
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['DATABASE'] = 'server.db'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024


SMTP_SERVER = "smtp.mail.ru"
SMTP_PORT = 465
SMTP_USERNAME = ""
SMTP_PASSWORD = ""
FROM_EMAIL = ""


# ================================================
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn


def generate_token(user_email, token_type='access'):
    if token_type == 'access':
        expires = datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    else:
        expires = datetime.utcnow() + app.config['JWT_REFRESH_TOKEN_EXPIRES']

    payload = {
        'email': user_email,
        'exp': expires,
        'type': token_type
    }

    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        payload = verify_token(token)
        if not payload or payload['type'] != 'access':
            return jsonify({'message': 'Invalid or expired token!'}), 401

        return f(payload['email'], *args, **kwargs)

    return decorated


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def reload_token(email):
    with get_db() as db:
        new_access_token = generate_token('email')
        new_refresh_token = generate_token(email, 'refresh')

        db.execute('''
                UPDATE refresh_tokens 
                SET token = ?
                WHERE email = ?
                ''', (new_refresh_token, email))
        db.commit()
        return new_access_token, new_refresh_token


def transform_structure(original_data):
    transformed = {}

    for group in original_data.get('groups', []):
        group_name = group.get('name', '')
        sections_dict = {}

        for section in group.get('sections', []):
            section_code = section.get('code', '')
            section_name = section.get('name', '').lower().capitalize()
            section_key = f"{section_code} {section_name}"

            specialties_list = [
                {"code": spec.get('code', ''), 'name': spec.get('name', '')}
                for spec in section.get('specialties', [])
            ]

            sections_dict[section_key] = specialties_list

        if group_name and sections_dict:
            transformed[group_name] = sections_dict

    return transformed


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def send_verification_code(email, code):
    message = MIMEText(f"Ваш код верификации: {code}")
    message['Subject'] = "Код верификации"
    message['From'] = FROM_EMAIL
    message['To'] = email

    try:
        if debugMail:
            return True
        server = smtplib.SMTP_SSL('smtp.mail.ru', 465)
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(FROM_EMAIL, email, message.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


def get_user_by_token(token):
    with get_db() as db:
        email = db.execute('''
        SELECT email FROM refresh_tokens 
        WHERE token = ?
        ''', (token,)).fetchone()['email']

        user = db.execute('''
        SELECT * FROM users where email = ?
        ''', (email,)).fetchone()

        db.commit()
        return user if user else None


def get_user_by_email(email):
    with get_db() as db:
        user = db.execute('''
        SELECT * FROM users where email = ?
        ''', (email,)).fetchone()
        db.commit()
        return user if user else None


@app.route('/speciality', methods=['POST'])
def set_speciality():
    data = request.get_json()
    specialities = data['specialties']
    print("Токен при сохранении специальностей", data['token']['refreshToken'])
    user = get_user_by_token(data['token']['refreshToken'])
    new_access_token, new_refresh_token = reload_token(user['email'])
    with get_db() as db:
        db.execute('''
        DELETE FROM selected_speciality where user_id = ?
        ''', (user['id'],)).fetchone()
        for speciality in specialities:
            db.execute('''INSERT INTO selected_speciality (user_id, code, name) values (?, ?, ?)''',
                       (user['id'], speciality.split()[0],
                        speciality.replace(f'{speciality.split()[0]} ', ''),),
                       )
        db.execute('''UPDATE users set state = ? where id = ?''', (
            2 if user['state'] == 2 else 4 if user['state'] == 4 else 1, user['id']),
                   )

        db.commit()
    return jsonify({
        'refreshToken': new_refresh_token,
    })


@app.route('/speciality', methods=['GET'])
def get_speciality():
    try:
        with open('parsers/education_structure.json', 'r', encoding='utf-8') as f:
            original_data = json.load(f)
        transformed_data = transform_structure(original_data)
        return jsonify(transformed_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/subject', methods=["POST"])
def set_subject():
    data = request.get_json()
    subjects = data['subjects']
    print("Токен при сохранении предметов", data['token']['refreshToken'])
    user = get_user_by_token(data['token']['refreshToken'])

    with get_db() as db:
        db.execute('''
        DELETE FROM selected_subject where user_id = ?
        ''', (user['id'],)).fetchone()

        for subject in subjects:
            ball = subject.get('ball', None)
            db.execute('''INSERT INTO selected_subject (user_id, subject, ball) values (?, ?,?)''',
                       (user['id'], subject['subject'], ball), )

        db.execute('''UPDATE users set state = ? where id = ?''', (2, user['id']), )
        db.commit()
    new_access_token, new_refresh_token = reload_token(user['email'])
    return jsonify({
        'refreshToken': new_refresh_token,
        'accessToken': new_access_token
    })


@app.route('/toggle_favorite', methods=["POST"])
def toggle_favorite():
    data = request.get_json()
    user = get_user_by_token(data['token']['refreshToken'])
    programId = data['programId']
    with get_db() as db:
        if (db.execute('''
    SELECT * FROM favorites WHERE user_id = ? and program_id = ?
    ''', (user['id'], programId), ).fetchone() is not None):
            db.execute('''
            DELETE FROM favorites WHERE user_id = ? and program_id = ?
            ''', (user['id'], programId), )
        else:
            db.execute('''
            INSERT INTO favorites (user_id, program_id) values (?, ?)
            ''', (user['id'], programId), )
    new_access_token, new_refresh_token = reload_token(user['email'])
    return jsonify({
        'refreshToken': new_refresh_token,
        'accessToken': new_access_token
    })


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if not user:
            return jsonify({
                'error': 'User not found',
                'isUserExists': False
            }), 404

        if check_password(password, user['password']):
            refresh_token = generate_token(email, 'refresh')
            db.execute('INSERT OR REPLACE INTO refresh_tokens (email, token) VALUES (?, ?)',
                       (email, refresh_token))
            db.commit()
            return jsonify({
                'isUserExists': True,
                'refreshToken': refresh_token,
                'state': user['state']
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    with get_db() as db:
        user_exists = db.execute('SELECT 1 FROM users WHERE email = ?', (email,)).fetchone()
        if user_exists:
            return jsonify({'error': 'User already exists'}), 400
        verification_code = secrets.randbelow(900000) + 100000  # 6-значный код
        hashed_password = hash_password(password)

        if send_verification_code(email, verification_code):
            db.execute('''
            INSERT INTO verification_codes (email, code, password) 
            VALUES (?, ?, ?)
            ''', (email, str(verification_code), hashed_password))
            db.commit()

            refresh_token = generate_token(email, 'refresh')
            db.execute('INSERT INTO refresh_tokens (email, token) VALUES (?, ?)',
                       (email, refresh_token))
            db.commit()

            return jsonify({
                'refreshToken': refresh_token,
                'message': 'Verification code sent to email'
            })
        else:
            return jsonify({'error': 'Failed to send verification code'}), 500


@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    email = data.get('email')
    code = data.get('verificationCode')

    if not email or not code:
        return jsonify({'error': 'Email and verification code are required'}), 400

    with get_db() as db:
        verification_data = db.execute('''
        SELECT * FROM verification_codes 
        WHERE email = ? AND code = ?
        ''', (email, code)).fetchone()

        if not verification_data:
            return jsonify({'error': 'No verification request for this email or invalid code'}), 400

        # Проверяем срок действия кода (10 минут)
        created_at = datetime.strptime(verification_data['created_at'], '%Y-%m-%d %H:%M:%S')
        if datetime.utcnow() - created_at > timedelta(minutes=10):
            db.execute('DELETE FROM verification_codes WHERE email = ?', (email,))
            db.commit()
            return jsonify({'error': 'Verification code expired'}), 400

        # Код верный - регистрируем пользователя
        db.execute('''
        INSERT INTO users (email, password, verified) 
        VALUES (?, ?, ?)
        ''', (email, verification_data['password'], True))

        # Удаляем использованный код
        db.execute('DELETE FROM verification_codes WHERE email = ?', (email,))

        # Генерируем новые токены
        access_token = generate_token(email)
        refresh_token = generate_token(email, 'refresh')

        # Обновляем refresh токен
        db.execute('''
        UPDATE refresh_tokens 
        SET token = ? 
        WHERE email = ?
        ''', (refresh_token, email))
        db.commit()

        return jsonify({
            'isVerified': True,
            'accessToken': access_token,
            'refreshToken': refresh_token
        })


@app.route('/refresh', methods=['POST'])
def refresh():
    data = request.get_json()
    refresh_token = data.get('refreshToken')
    if not refresh_token:
        return jsonify({'error': 'Refresh token is required'}), 400
    payload = verify_token(refresh_token)

    if not payload or payload['type'] != 'refresh':
        return jsonify({'error': 'Invalid or expired refresh token'}), 401
    email = payload['email']
    user = get_user_by_email(email)
    with get_db() as db:
        stored_token = db.execute('''
        SELECT token FROM refresh_tokens 
        WHERE email = ?
        ''', (email,)).fetchone()
        if not stored_token or stored_token['token'] != refresh_token:
            print(refresh_token, '\n', stored_token)
            return jsonify({'error': 'Refresh token is no longer valid'}), 401

        new_access_token = generate_token(email)
        new_refresh_token = generate_token(email, 'refresh')

        db.execute('''
        UPDATE refresh_tokens 
        SET token = ?
        WHERE email = ?
        ''', (new_refresh_token, email))
        db.commit()

        return jsonify({
            'state': user['state'],
            'refreshToken': new_refresh_token,
            'accessToken': new_access_token
        })


@app.route('/loadprograms', methods=['POST'])
def recommendations():
    with get_db() as db:
        try:
            data = request.get_json()
            print("Токен при получении программ", data['token']['refreshToken'])
            user = get_user_by_token(data['token']['refreshToken'])
            is_favorites = data['isFavorites']
            result = get_programs_for_user(user, is_favorites)
            chunk_size = request.args.get('chunk_size', default=20, type=int)
            chunk_number = request.args.get('chunk', default=0, type=int)
            chunk_size = max(20, min(chunk_size, 40))

            start_idx = chunk_number * chunk_size
            end_idx = start_idx + chunk_size

            chunk_programs = result[start_idx:end_idx]

            response_data = {
                'data': chunk_programs,
                'total': len(result),
                'chunkSize': chunk_size,
                'chunk': chunk_number,
                'hasMore': end_idx < len(result)
            }
        except Exception as e:
            print(e)
            return jsonify({'error': str(e)}), 500
    db.close()
    return jsonify(response_data)


@app.route('/spo', methods=['POST'])
def setSPO():
    data = request.get_json()
    user = get_user_by_token(data['refreshToken'])

    with get_db() as db:
        db.execute('''
                UPDATE users set state = ? where id = ?
                ''', (4, user['id'],), )

    new_access_token, new_refresh_token = reload_token(user['email'])
    return jsonify({
        'refreshToken': new_refresh_token,
        'accessToken': new_access_token
    })


@app.route('/save_bonus', methods=['POST'])
def save_bonus():
    data = request.get_json()
    user = get_user_by_token(data['token']['refreshToken'])
    bonus = data['bonus']
    with get_db() as db:
        db.execute('''
                UPDATE users set gold_gto = ?, perfect_attestat = ?, perfect_spo = ?, portfolio = ?, volunteering = ?, 
                essay = ? where id = ?
                ''', (
            bonus['isGTO'],
            bonus['isPefectAttestat'],
            bonus['isPerfectSPO'],
            bonus['isPortfolio'],
            bonus['isVolunteer'],
            bonus['isEssay'],
            user['id'],), )

    new_access_token, new_refresh_token = reload_token(user['email'])
    return jsonify({
        'refreshToken': new_refresh_token,
        'accessToken': new_access_token
    })


@app.route('/profile', methods=['POST'])
def profile():
    data = request.get_json()
    user = get_user_by_token(data['refreshToken'])
    new_access_token, new_refresh_token = reload_token(user['email'])
    bonus = {"isGTO": bool(user['gold_gto']), "isPefectAttestat": bool(user['perfect_attestat']),
                  "isPerfectSPO": bool(user['perfect_spo']), "isPortfolio": bool(user['portfolio']),
                  "isVolunteer": bool(user['volunteering']), "isEssay": bool(user['essay'])}
    result = {
        'email': user['email'],
        'state': user['state'],
        'bonus': bonus,
        'subjects': [],
        'specialities': [],
        'refreshToken': new_refresh_token
    }

    with get_db() as db:
        subjects = db.execute('''
        SELECT * FROM selected_subject where user_id = ?''', (user['id'],)).fetchall()
        for subject in subjects:
            if subject['subject']:
                result['subjects'].append({'subject': subject["subject"], 'ball': subject["ball"]})
        specialities = db.execute('''
        SELECT * FROM selected_speciality where user_id = ?''', (user['id'],)).fetchall()

        for speciality in specialities:
            result['specialities'].append(f"{speciality['code']} {speciality['name']}")
    return jsonify(result)


def get_programs_for_user(user, is_favorites):
    state = user['state']
    user_id = user['id']
    if state == 1:
        query = """
        SELECT p.*, u.full_title, u.short_title
        FROM programs p, universities u
        JOIN selected_speciality ss ON p.code = ss.code AND ss.user_id = ?
        where u.id = p.university_id
        """
        params = (user_id,)
    elif state in [2, 3]:
        query = """
                SELECT p.*, u.full_title, u.short_title
FROM programs p,
     universities u
         JOIN selected_speciality ss ON p.code = ss.code AND ss.user_id = ?
WHERE u.id = p.university_id
  AND p.predict_ball IS NOT NULL
  AND (SELECT COUNT(*)
       FROM exams e
       WHERE e.program_id = p.id
         AND e.is_choice = 1
         AND EXISTS (SELECT 1
                     FROM selected_subject s
                     WHERE s.user_id = ?
                       AND s.subject = e.subject)) > 0
  AND p.id IN (SELECT e.program_id
               FROM exams e
               WHERE (
                         (e.is_choice = 0 AND EXISTS (SELECT 1
                                                      FROM selected_subject s
                                                      WHERE s.user_id = ?
                                                        AND s.subject = e.subject
                                                        AND e.subject NOT LIKE '%ДВИ%'))
                         )
               GROUP BY e.program_id
               HAVING COUNT(CASE WHEN e.is_choice = 0 AND e.subject NOT LIKE '%ДВИ%' THEN 1 END) = (SELECT COUNT(*)
                                                                                                    FROM exams e2
                                                                                                    WHERE e2.program_id = e.program_id
                                                                                                      AND e2.is_choice = 0
                                                                                                      AND e2.subject NOT LIKE '%ДВИ%'))
                """
        params = (user_id, user_id, user_id)
    elif state == 4:
        query = """
                SELECT p.*, u.full_title, u.short_title
                FROM programs p, universities u
                JOIN selected_speciality ss ON p.code = ss.code AND ss.user_id = ?
                where u.id = p.university_id and p.is_spo = 1
                """
        params = (user_id,)
    else:
        return []
    with get_db() as db:
        programs = db.execute(query, params).fetchall()
        result = []
        for program in programs:
            favorites = db.execute('''select * from favorites where program_id = ? and user_id = ?''',
                                   (program['id'], user_id,)).fetchone()
            if is_favorites and not favorites:
                continue

            if user['state'] == 4:
                addmission_chance = -1

                exams = db.execute('''
                                                SELECT 
                                                    subject,
                                                    min_score,
                                                    is_choice
                                                FROM introductory
                                                WHERE program_id = ?
                                            ''', (program['id'],)).fetchall()
            else:
                exams = db.execute('''
                                SELECT 
                                    exam_type,
                                    subject,
                                    min_score,
                                    is_choice
                                FROM exams
                                WHERE program_id = ?
                            ''', (program['id'],)).fetchall()

                user_exams = db.execute('''
                                SELECT * FROM selected_subject WHERE user_id = ?
                            ''', (user_id,)).fetchall()

                addmission_chance = calculate_admission_chance(
                    [program['gold_gto'], program['perfect_attestat'], program['perfect_spo'],
                     program['portfolio'], program['volunteering'], program['essay']],

                    [user['gold_gto'], user['perfect_attestat'], user['perfect_spo'],
                     user['portfolio'], user['volunteering'], user['essay']],

                    program['predict_ball'],

                    program['sigma'],

                    exams,

                    user_exams,
                )

            program_data = {
                'id': program['id'],
                'admission_chance': addmission_chance,
                'code': program['code'],
                'name': program['name'].replace('‐', '-'),
                'isFavorite': favorites is not None,
                'university': program['short_title'],
                'universityFull': program['full_title'],
                'predict_ball': program['predict_ball'],
                'pref_ball': program['pref_ball'],
                'exams': [{
                    'type': 'required' if exam['is_choice'] == 0 else 'choice',
                    'subject': exam['subject'],
                    'min': exam['min_score']
                } for exam in exams]
            }
            result.append(program_data)
        result.sort(key=lambda x: x['admission_chance'], reverse=True)
        return result


def calculate_admission_chance(
        bonus_list: List[int],
        bonus_user: List[bool],
        avg_passing_score: float,
        avg_deviation: float,
        program_exams: List[Dict],
        user_exams: List[Dict]
):
    try:
        bonus = [num for num, m in zip(bonus_list, bonus_user) if m == 1]
        user_scores = {exam['subject']: exam['ball'] for exam in user_exams}
        mandatory_exams = []
        optional_exams = []
        for exam in program_exams:
            if exam['is_choice'] == 0 or exam['exam_type'].lower() == 'required':

                mandatory_exams.append(exam)
            else:
                optional_exams.append(exam)
        mandatory_exams = [dict(row) for row in mandatory_exams]
        optional_exams = [dict(row) for row in optional_exams]

        for exam in mandatory_exams:
            subject = exam['subject']
            min_score = int(exam['min_score'])
            if subject not in user_scores:
                return -1
            if user_scores[subject] < min_score:
                return 0
        if optional_exams:
            valid_optional_exams = []
            for exam in optional_exams:
                subject = exam['subject']
                min_score = int(exam['min_score'])
                if subject not in user_scores or user_scores[subject] is None:
                    continue
                if subject in user_scores and user_scores[subject] >= min_score:
                    valid_optional_exams.append((subject, user_scores[subject]))
            if not valid_optional_exams:
                return 0

            best_optional_subject, best_optional_score = max(valid_optional_exams, key=lambda x: x[1])
            mandatory_exams = [row['subject'] for row in mandatory_exams]
            for exam in user_exams:
                subject = exam['subject']
                if subject not in mandatory_exams and subject != best_optional_subject:
                    del user_scores[subject]

        if not user_scores:
            return 0

        sum_ball = sum(user_scores.values()) + min(sum(bonus), 10)

        z_score = (sum_ball - avg_passing_score) / avg_deviation
        percentile = stats.norm.cdf(z_score) * 100
        return min(round(percentile, 0), 90)
    except Exception as e:
        print(e, "DAD")
        return -1


if __name__ == '__main__':
    app.run(debug=True)
