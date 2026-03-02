"""
sb_consumers.py — WebSocket consumer для морского боя.

Эндпоинты:
  ws/seabattle/<lobby_id>/lobby/  — общий канал (ожидание + игра)
"""
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from mainapp.models import SeaBattleLobby


class SeaBattleConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.user = self.scope["user"]
        if not self.user.is_authenticated:
            await self.close()
            return

        self.lobby_id  = self.scope["url_route"]["kwargs"].get("lobby_id")
        self.group_name = f"seabattle_lobby_{self.lobby_id}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)
        await self._delete_if_empty(self.user.id)

    async def receive(self, text_data=None, bytes_data=None):
        pass

    # ── Групповые обработчики ─────────────────────────────────────────────────

    async def sb_opponent_joined(self, event):
        await self.send(text_data=json.dumps({
            "type":     "opponent_joined",
            "opponent": event["opponent"],
        }))

    async def sb_player_ready(self, event):
        await self.send(text_data=json.dumps({
            "type":       "player_ready",
            "user_id":    event["user_id"],
            "both_ready": event["both_ready"],
            "first_turn": event["first_turn"],
        }))

    async def sb_shot(self, event):
        uid = self.user.id
        await self.send(text_data=json.dumps({
            "type":        "shot",
            "shooter_id":  event["shooter_id"],
            "row":         event["row"],
            "col":         event["col"],
            "hit":         event["hit"],
            "game_over":   event["game_over"],
            "winner":      event["winner"],
            "is_your_turn": event["next_turn"] == uid,
            "timestamp":   event["timestamp"],
        }))

    async def sb_lobby_deleted(self, event):
        await self.send(text_data=json.dumps({"type": "lobby_deleted"}))

    # ── Вспомогательные ───────────────────────────────────────────────────────

    @database_sync_to_async
    def _delete_if_empty(self, user_id):
        try:
            lobby = SeaBattleLobby.objects.get(id=self.lobby_id)
            if lobby.lobby_owner == user_id and lobby.opponent is None:
                lobby.delete()
        except SeaBattleLobby.DoesNotExist:
            pass