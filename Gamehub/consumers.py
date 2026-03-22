import json
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from mainapp.models import GameLobby, User
from mainapp.views import _broadcast_group

TURN_TIMEOUT = 120  # секунд


class TicTacToeConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.user = self.scope["user"]
        if not self.user.is_authenticated:
            await self.close()
            return

        self.lobby_id   = self.scope["url_route"]["kwargs"].get("lobby_id")
        self.group_name = f"tictactoe_lobby_{self.lobby_id}"
        self._timeout_task = None

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        lobby = await self._get_lobby()
        if lobby:
            is_your_turn = lobby.turn == self.user.id
            await self.send(text_data=json.dumps({
                "type":        "lobby_state",
                "lobby_id":    lobby.id,
                "map":         lobby.map,
                "is_your_turn": is_your_turn,
            }))
            # Если игра идёт и сейчас мой ход — запускаем таймер
            if is_your_turn and lobby.opponent is not None:
                await self._start_timeout(True)

    async def disconnect(self, code):
        await self._cancel_timeout()
        await self.channel_layer.group_discard(self.group_name, self.channel_name)
        await self._delete_lobby(self.user.id)

    async def receive(self, text_data=None, bytes_data=None):
        pass

    # ── Групповые обработчики ─────────────────────────────────────────────────

    async def opponent_found(self, event):
        await self._cancel_timeout()
        await self._start_timeout(event.get("is_your_turn", False))
        await self.send(text_data=json.dumps({
            "type":        "found_opponent",
            "opponent":    event["opponent"],
            "is_your_turn": event["is_your_turn"],
            "map":         event.get("map"),
            "board_size":  event.get("board_size"),
            "win_length":  event.get("win_length"),
            "my_symbol":   event.get("my_symbol", "X"),
        }))

    async def turn_made(self, event):
        next_turn_user_id = event.get("next_turn_user_id")
        is_your_turn = (next_turn_user_id == self.user.id) if next_turn_user_id else False

        await self._cancel_timeout()
        if is_your_turn and not event.get("game_over"):
            await self._start_timeout(True)

        await self.send(text_data=json.dumps({
            "type":        "get_turn",
            "row":         event["row"],
            "col":         event["col"],
            "map":         event["map"],
            "is_your_turn": is_your_turn,
            "game_over":   event.get("game_over"),
            "winner":      event.get("winner"),
            "timestamp":   event["timestamp"],
        }))

    async def game_ended(self, event):
        await self._cancel_timeout()
        await self.send(text_data=json.dumps({
            "type":   "game_ended",
            "winner": event.get("winner"),
            "map":    event.get("map"),
        }))

    async def opponent_disconnected(self, event):
        await self.send(text_data=json.dumps({
            "message": "player leaved",
            "type": "opponent_disconnected",
            "user_email":event.get("user_email"),
        }))

    # ── Таймаут ───────────────────────────────────────────────────────────────

    async def _start_timeout(self, is_my_turn: bool):
        """Запустить таймер только если сейчас МОЙ ход."""
        if not is_my_turn:
            return
        self._timeout_task = asyncio.ensure_future(self._timeout_loop())

    async def _cancel_timeout(self):
        if self._timeout_task and not self._timeout_task.done():
            self._timeout_task.cancel()
            try:
                await self._timeout_task
            except asyncio.CancelledError:
                pass
        self._timeout_task = None

    async def _timeout_loop(self):
        """Ждём TURN_TIMEOUT секунд. Если ход не был сделан — проигрыш."""
        await asyncio.sleep(TURN_TIMEOUT)
        # Проверяем что лобби ещё существует и ход всё ещё за нами
        result = await self._forfeit_if_timeout()
        if result:
            lobby_id, winner_id, board = result
            group = f"tictactoe_lobby_{lobby_id}"
            await self.channel_layer.group_send(group, {
                "type":      "game_ended",
                "winner":    winner_id,
                "map":       board,
                "reason":    "timeout",
            })

    # ── DB ────────────────────────────────────────────────────────────────────

    @database_sync_to_async
    def _get_lobby(self):
        try:
            return GameLobby.objects.get(id=self.lobby_id)
        except GameLobby.DoesNotExist:
            return None

    @database_sync_to_async
    def _delete_lobby(self, user_id):
        try:
            lobby = GameLobby.objects.get(id=self.lobby_id)
            group_name = f"tictactoe_lobby_{lobby.id}"
            _broadcast_group(group_name, {"type": "opponent_disconnected", "user_email": User.objects.get(id=user_id).email })
            lobby.delete()
        except GameLobby.DoesNotExist:
            pass

    @database_sync_to_async
    def _forfeit_if_timeout(self):
        """
        Если ход всё ещё за текущим пользователем — засчитать ему поражение.
        Возвращает (lobby_id, winner_id, board) или None.
        """
        from django.utils import timezone
        try:
            lobby = GameLobby.objects.get(id=self.lobby_id)
        except GameLobby.DoesNotExist:
            return None

        # Игра уже закончена
        if lobby.turn is None or lobby.winner is not None:
            return None

        # Ход не за нами — таймер не должен был запуститься, но на всякий случай
        if lobby.turn != self.user.id:
            return None

        # Проверяем дедлайн
        if lobby.turn_deadline and timezone.now() < lobby.turn_deadline:
            return None

        # Засчитываем поражение текущему игроку
        winner_id = lobby.opponent if lobby.lobby_owner == self.user.id else lobby.lobby_owner
        lobby.winner   = winner_id
        lobby.turn     = None
        lobby.turn_deadline = None
        lobby.save()
        lobby.delete()

        return (self.lobby_id, winner_id, lobby.map)