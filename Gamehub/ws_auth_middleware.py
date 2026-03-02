"""
ws_auth_middleware.py — JWT аутентификация для WebSocket через query string.

Читает токен из ?token=<access_token> и кладёт пользователя в scope["user"].
Это необходимо потому что браузер не может передать Authorization header
при WebSocket-подключении.
"""
from urllib.parse import parse_qs
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


@database_sync_to_async
def get_user_from_token(token_key):
    from mainapp.models import User
    try:
        token = AccessToken(token_key)
        user_id = token["user_id"]
        return User.objects.get(id=user_id)
    except (InvalidToken, TokenError, User.DoesNotExist, KeyError):
        return AnonymousUser()


class JwtAuthMiddleware:
    """
    Middleware который читает JWT из query string (?token=...) 
    и аутентифицирует пользователя для WebSocket соединения.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        query_string = scope.get("query_string", b"").decode()
        params = parse_qs(query_string)
        token_list = params.get("token", [])

        if token_list:
            scope["user"] = await get_user_from_token(token_list[0])
        else:
            scope["user"] = AnonymousUser()

        return await self.app(scope, receive, send)