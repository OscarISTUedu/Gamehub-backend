# backend/Dockerfile.prod (упрощенная версия)
FROM python:3.11-slim

WORKDIR /app

# Установка системных зависимостей
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Установка переменных окружения
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Копирование и установка зависимостей
COPY req.txt .
RUN pip install --no-cache-dir -r req.txt

# Копирование проекта
COPY . .
