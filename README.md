# Gamehub Project - Как развернуть?

## Вариант 1: Локально через .env

### Создать и активировать .env

**Windows:**
```bash
python -m venv env
env\Scripts\activate
```
**Linux:**
```bash
python3 -m venv env
source env/bin/activate
```
### Установить зависимости
```bash
pip install -r req.txt
```
### Запустить приложение
```bash
daphne Gamehub.asgi:application --bind 127.0.0.1 --port 8000
```
## Вариант 2: Запуск в докер контейнере
```bash
docker-compose up
```
## Конфигурация nginx
Оба варианта настройки не включают автоматическое развертывание Nginx. Используйте эту конфигурацию для Nginx:
```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;
    
    server_name 91.132.58.57;

    location /api {
        proxy_pass http://127.0.0.1:8000/api;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /static/img {
        root /root/Gamehub-backend;
    }

    location /media/user_avatars {
        root /root/Gamehub-backend;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```
