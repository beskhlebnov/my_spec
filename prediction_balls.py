import os
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.linear_model import LinearRegression

from app import get_db


def predict_passing_score(
        university=None,
        code=None,
        program_name=None,
        verbose=False,
        weighted_regression=True,
        outlier_removal=False
):
    if 'df' not in globals():
        df = pd.read_csv('statistic/_ВСЕ_/2021-2024.csv')

    if code is not None:
        filtered_data = df[(df['Код специальности'] == code) & (df['Вуз'] == university)]
    elif program_name is not None:
        filtered_data = df[(df['Направление'].str.contains(program_name, case=False)) & (df['Вуз'] == university)]
    else:
        return None, "Укажите код специальности (code) или её название (program_name)"

    if len(filtered_data) == 0:
        return None, "Данные не найдены. Проверьте код/название специальности и вуз."
    if len(filtered_data) < 2:
        return None, "Недостаточно данных для прогноза (нужно минимум 2 года данных)"

    X = filtered_data['Год'].values.reshape(-1, 1)
    y = filtered_data['Проходной балл (очная форма)'].values
    sigma = np.std(y)
    warning = None
    if outlier_removal:
        Q1 = np.percentile(y, 25)
        Q3 = np.percentile(y, 75)
        IQR = Q3 - Q1
        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR

        outliers_mask = (y < lower_bound) | (y > upper_bound)
        outliers_years = filtered_data['Год'][outliers_mask].tolist()

        if outliers_years:
            warning = f"Обнаружены выбросы в годах: {outliers_years}. Они будут исключены."
            X = X[~outliers_mask]
            y = y[~outliers_mask]
            if len(X) < 2:
                return None, "После удаления выбросов осталось слишком мало данных"

    weights = None
    if weighted_regression and len(X) >= 2:
        weights = np.linspace(1, 3, num=len(X))
        if verbose:
            print(f"Веса регрессии: {dict(zip(X.flatten(), weights))}")

    model = LinearRegression()
    model.fit(X, y, sample_weight=weights) if weights is not None else model.fit(X, y)

    predicted_score = int(round(model.predict([[2025]])[0]))
    return predicted_score, warning, sigma


def merge_csv_from_subfolders(parent_folder, output_file="merged_dataset.csv"):
    if not os.path.exists(parent_folder):
        print(f"Ошибка: папка '{parent_folder}' не существует!")
        return None

    all_data = []

    for csv_file in Path(parent_folder).rglob("*.csv"):
        try:
            df = pd.read_csv(csv_file)
            all_data.append(df)
            print(f"Добавлен файл: {csv_file}")
        except Exception as e:
            print(f"Ошибка чтения {csv_file}: {e}")

    if not all_data:
        print("CSV-файлы не найдены!")
        return None

    merged_df = pd.concat(all_data, ignore_index=True)
    merged_df.to_csv(output_file, index=False)
    print(f"Результат сохранён в: {output_file}")

    return merged_df


def get_predict():
    with get_db() as db:
        unversities = db.execute('''SELECT * FROM universities''').fetchall()
        for university in unversities:
            specs = db.execute('''SELECT * FROM programs where university_id = ?''', (university['id'],)).fetchall()
            for spec in specs:
                predicted_score, warning, sigma = predict_passing_score(code=spec['code'], university=university['short_title'])
                print(spec['code'], predicted_score, university['short_title'])
                if predicted_score is not None:
                    db.execute('''UPDATE programs set predict_ball = ?, sigma = ? where id = ?''',
                               (predicted_score, sigma, spec['id']),).fetchall()
                db.commit()
