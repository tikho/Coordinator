# Используем официальный Python 3.9 как базовый образ
FROM python:3.9-slim

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Удаляем старое в /app
RUN rm -rf /app/*

# Копируем все файлы проекта в контейнер
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь проект в контейнер
COPY . .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Открываем порты для связи с контейнером (если нужно)
EXPOSE 8080

# Команда для запуска бота
CMD ["python", "main/main.py"]

