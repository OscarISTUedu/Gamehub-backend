FROM python:3.11-slim-bookworm

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY req.txt .
RUN pip install --no-cache-dir -r req.txt

COPY . .

# Удаляем старую проблемную миграцию если вдруг осталась
RUN rm -f /app/mainapp/migrations/0002_gamelobby_board_size_win_length.py

CMD ["sh", "-c", \
    "python manage.py migrate --fake-initial --noinput && \
     daphne -b 0.0.0.0 -p 8000 Gamehub.asgi:application"]