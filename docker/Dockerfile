# Минимальный образ для веб-UI и загрузчиков данных
FROM python:3.11-slim AS app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Установка зависимостей рантайма
# Файл зависимостей лежит в корне контекста сборки
COPY requirements-app.txt ./requirements-app.txt
RUN pip install --no-cache-dir -r ./requirements-app.txt

# Копирование файлов проекта
COPY . ./

# Порт по умолчанию
EXPOSE 8000

# Запуск приложения FastAPI
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
