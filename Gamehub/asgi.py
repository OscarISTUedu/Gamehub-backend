import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import path

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Gamehub.settings')

django_asgi_app = get_asgi_application()

from Gamehub.consumers import TicTacToeConsumer
from Gamehub.sb_consumers import SeaBattleConsumer
from Gamehub.ws_auth_middleware import JwtAuthMiddleware

websocket_urlpatterns = [
    # TicTacToe
    path('ws/tictactoe/<int:lobby_id>/found_opponent/', TicTacToeConsumer.as_asgi()),
    path('ws/tictactoe/<int:lobby_id>/get_turn/',       TicTacToeConsumer.as_asgi()),
    # SeaBattle
    path('ws/seabattle/<int:lobby_id>/lobby/',          SeaBattleConsumer.as_asgi()),
]

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": JwtAuthMiddleware(
        URLRouter(websocket_urlpatterns)
    ),
})