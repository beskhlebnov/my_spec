import json
import sqlite3


def create_database():
    conn = sqlite3.connect('server.db')
    cursor = conn.cursor()

    # Создаем таблицу для университетов
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS universities (
        id TEXT PRIMARY KEY,
        short_title TEXT,
        full_title TEXT,
        city TEXT
    )
    ''')

    # Создаем таблицу для образовательных программ
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS programs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        university_id TEXT,
        code TEXT,
        name TEXT,
        pref_ball INT,
        predict_ball INT,
        FOREIGN KEY (university_id) REFERENCES universities (id)
    )
    ''')

    # Создаем таблицу для экзаменов
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS exams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id INTEGER,
        exam_type TEXT,
        subject TEXT,
        min_score TEXT,
        is_choice INTEGER DEFAULT 0,
        FOREIGN KEY (program_id) REFERENCES programs (id)
    )
    ''')

    conn.commit()
    conn.close()


def import_data_from_json(json_file):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    conn = sqlite3.connect('server.db')
    cursor = conn.cursor()

    for university in data:
        cursor.execute('''
        INSERT OR IGNORE INTO universities (id, short_title, full_title, city)
        VALUES (?, ?, ?, ?)
        ''', (university['id'], university['short_title'], university['full_title'], university['city']))

        for program in university['programs']:
            if not program.get('exams'):
                continue

            bonus_fields = {
                'gold_gto': 0,
                'perfect_attestat': 0,
                'perfect_spo': 0,
                'portfolio': 0,
                'essay': 0,
                'volunteering': 0
            }

            for bonus_item in program.get('bonus', []):
                for key, value in bonus_item.items():
                    if key == 'Золотой значок ГТО':
                        bonus_fields['gold_gto'] = int(value)
                    elif key == 'Аттестат с отличием':
                        bonus_fields['perfect_attestat'] = int(value)
                    elif key == 'Диплом СПО с отличием':
                        bonus_fields['perfect_spo'] = int(value)
                    elif key == 'Портфолио/олимпиады':
                        bonus_fields['portfolio'] = int(value)
                    elif key == 'Итоговое сочинение':
                        bonus_fields['essay'] = int(value)
                    elif key == 'Волонтерство':
                        bonus_fields['volunteering'] = int(value)

            is_spo = 0 if not program.get('introductory', []) else 1

            cursor.execute('''
            INSERT INTO programs (university_id, code, name, pref_ball, is_spo, gold_gto, perfect_attestat, 
            perfect_spo, portfolio, volunteering, essay)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (university['id'], program['code'], program['name'], program['pref_ball'], is_spo,
                  bonus_fields['gold_gto'], bonus_fields['perfect_attestat'], bonus_fields['perfect_spo'],
                  bonus_fields['portfolio'], bonus_fields['volunteering'], bonus_fields['essay'],))
            program_id = cursor.lastrowid

            for intro in program.get('introductory', []):
                choices = intro.get('subjects', [])
                if choices:
                    print(choices)
                    for choice in intro.get('subjects', []):
                        cursor.execute('''
                                INSERT INTO introductory (
                                    program_id, subject, min_score, is_choice
                                ) VALUES (?, ?, ?, ?)
                            ''', (program_id, choice['subject'], int(choice.get('min_score', 0)), 1
                                  ))
                else:
                    cursor.execute('''INSERT INTO introductory (
                                                        program_id, subject, min_score, is_choice
                                                    ) VALUES (?, ?, ?, ?)
                                                ''', (program_id, intro['subject'], int(intro.get('min', 0)), 0
                                                      ))

            for exam in program['exams']:
                if exam['type'] == 'required':
                    cursor.execute('''
                    INSERT INTO exams (program_id, exam_type, subject, min_score)
                    VALUES (?, ?, ?, ?)
                    ''', (program_id, exam['type'], exam['subject'], exam['min']))
                elif exam['type'] == 'choice':
                    for option in exam['options']:
                        cursor.execute('''
                        INSERT INTO exams (program_id, exam_type, subject, min_score, is_choice)
                        VALUES (?, ?, ?, ?, 1)
                        ''', (program_id, exam['type'], option['name'], option['min']))

    conn.commit()
    conn.close()


if __name__ == '__main__':
    #create_database()
    import_data_from_json('universities.json')

    print("Данные успешно импортированы в базу данных.")
