import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from mainapp.models import GameLobby


class TicTacToeConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.user = self.scope["user"]
        if not self.user.is_authenticated:
            await self.close()
            return

        self.lobby_id = self.scope["url_route"]["kwargs"].get("lobby_id")
        self.group_name = f"tictactoe_lobby_{self.lobby_id}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        lobby = await self._get_lobby()
        if lobby:
            await self.send(text_data=json.dumps({
                "type": "lobby_state",
                "lobby_id": lobby.id,
                "map": lobby.map,
                "is_your_turn": lobby.turn == self.user.id,
            }))

    async def disconnect(self, code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

        # Если владелец отключился и противника ещё нет — удаляем лобби
        await self._delete_lobby_if_empty(self.user.id)

    async def receive(self, text_data=None, bytes_data=None):
        pass

    # ── Групповые обработчики ─────────────────────────────────────────────────

    async def opponent_found(self, event):
        await self.send(text_data=json.dumps({
            "type": "found_opponent",
            "opponent": event["opponent"],
            "is_your_turn": event["is_your_turn"],
            "map": event.get("map"),
            "board_size": event.get("board_size"),
            "win_length": event.get("win_length"),
        }))

    async def turn_made(self, event):
        next_turn_user_id = event.get("next_turn_user_id")
        is_your_turn = (next_turn_user_id == self.user.id) if next_turn_user_id else False

        await self.send(text_data=json.dumps({
            "type": "get_turn",
            "row": event["row"],
            "col": event["col"],
            "map": event["map"],
            "is_your_turn": is_your_turn,
            "game_over": event.get("game_over"),
            "winner": event.get("winner"),
            "timestamp": event["timestamp"],
        }))

    async def game_ended(self, event):
        await self.send(text_data=json.dumps({
            "type": "game_ended",
            "winner": event.get("winner"),
            "map": event.get("map"),
        }))

    # ── Вспомогательные методы ────────────────────────────────────────────────

    @database_sync_to_async
    def _get_lobby(self):
        try:
            return GameLobby.objects.get(id=self.lobby_id)
        except GameLobby.DoesNotExist:
            return None

    @database_sync_to_async
    def _delete_lobby_if_empty(self, user_id):
        """Удалить лобби если пользователь — владелец и противника ещё нет."""
        try:
            lobby = GameLobby.objects.get(id=self.lobby_id)
            if lobby.lobby_owner == user_id and lobby.opponent is None:
                lobby.delete()
        except GameLobby.DoesNotExist:
            pass