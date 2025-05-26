import requests
from bs4 import BeautifulSoup
import pdfplumber
import json
import re
import os
from urllib.parse import urljoin


def extract_year_from_filename(filename):
    match = re.search(r'\d{4}', filename)
    return int(match.group()) if match else None


def detect_table_structure(table):
    if not table or len(table) < 2:
        return 2, False

    has_num_column = any(
        str(row[0]).strip().lower() in ('№', '№ п/п', '№\nп/п')
        for row in table[:2] if row
    )

    for i, row in enumerate(table):
        if not row:
            continue
        if any('проходной балл' in str(cell).lower() for cell in row if cell):
            return i + 2, has_num_column

    return 2, has_num_column


def parse_pdf_to_json(pdf_path, output_json):
    year = extract_year_from_filename(pdf_path)
    if not year:
        raise ValueError("Год не найден в названии файла!")

    data = {"год": year, "абитуриенты": []}

    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            table = page.extract_table()
            if not table:
                continue

            start_row, has_num_column = detect_table_structure(table)
            code_col = 1 if has_num_column else 0
            dir_col = code_col + 1
            scores_start_col = dir_col + 1

            for row in table[start_row:]:
                if not row or all(cell is None or str(cell).strip() == '' for cell in row):
                    continue

                code = str(row[code_col]).strip() if len(row) > code_col and row[code_col] else ""
                direction = str(row[dir_col]).strip() if len(row) > dir_col and row[dir_col] else ""

                def safe_convert(score):
                    try:
                        return int(str(score).strip()) if score and str(score).strip() else None
                    except ValueError:
                        return None

                full_time_col = scores_start_col
                part_time_col = scores_start_col + 1
                mixed_time_col = scores_start_col + 2

                full_time = safe_convert(row[full_time_col]) if len(row) > full_time_col else None
                part_time = safe_convert(row[part_time_col]) if len(row) > part_time_col else None
                mixed_time = safe_convert(row[mixed_time_col]) if len(row) > mixed_time_col else None

                data["абитуриенты"].append({
                    "код": code,
                    "направление": direction,
                    "проходной_балл_очной_формы": full_time,
                    "проходной_балл_заочной_формы": part_time,
                    "проходной_балл_очно_заочной_формы": mixed_time
                })

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

    return data


def download_and_process_pdfs():
    base_url = "https://rsue.ru"
    abitur_url = urljoin(base_url, "/abitur/")

    try:
        response = requests.get(abitur_url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        os.makedirs("pdf_files", exist_ok=True)
        os.makedirs("json_results", exist_ok=True)

        pdf_links = []
        for a in soup.find_all('a', href=re.compile(r'prohodnoy-ball-\d{4}\.pdf$')):
            href = a['href']
            pdf_url = urljoin(base_url, href)
            year = extract_year_from_filename(href)
            if year:
                pdf_links.append((year, pdf_url))

        for year, pdf_url in pdf_links:
            print(f"Обработка {year} года: {pdf_url}")

            pdf_filename = f"pdf_files/prohodnoy_ball_{year}.pdf"
            json_filename = f"json_results/prohodnoy_ball_{year}.json"

            try:
                pdf_response = requests.get(pdf_url)
                pdf_response.raise_for_status()

                with open(pdf_filename, 'wb') as f:
                    f.write(pdf_response.content)

                parse_pdf_to_json(pdf_filename, json_filename)
                print(f"Успешно обработан {year} год. Результаты сохранены в {json_filename}")

            except Exception as e:
                print(f"Ошибка при обработке {year} года: {e}")

    except Exception as e:
        print(f"Ошибка при получении страницы: {e}")


def process_pdf_files(folder_path, json_folder):
    if not os.path.exists(folder_path):
        print(f"Папка {folder_path} не существует!")
        return

    for filename in os.listdir(folder_path):
        if filename.lower().endswith('.pdf'):
            pdf_path = os.path.join(folder_path, filename)
            json_filename = os.path.splitext(filename)[0] + '.json'
            json_path = os.path.join(json_folder, json_filename)
            parse_pdf_to_json(pdf_path, json_path)
            print(f"Обработан файл: {filename} -> {json_filename}")

if __name__ == "__main__":
    process_pdf_files(input("Введите название папки с pdf файлами"), input("Введите путь куда сохранить результаты в json"))
    print("Обработка завершена!")