"""
sb_consumers.py — WebSocket consumer для морского боя.
"""
import json
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from mainapp.models import SeaBattleLobby

TURN_TIMEOUT = 120  # секунд


class SeaBattleConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.user = self.scope["user"]
        if not self.user.is_authenticated:
            await self.close()
            return

        self.lobby_id   = self.scope["url_route"]["kwargs"].get("lobby_id")
        self.group_name = f"seabattle_lobby_{self.lobby_id}"
        self._timeout_task = None

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        # При переподключении — запускаем таймер если сейчас наш ход
        lobby = await self._get_lobby()
        if lobby and lobby.owner_ready and lobby.opponent_ready and lobby.winner is None:
            is_my_turn = (lobby.turn == self.user.id)
            if is_my_turn:
                await self._start_timeout()

    async def disconnect(self, code):
        await self._cancel_timeout()
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
        # Когда оба готовы — запускаем таймер у того, чей первый ход
        if event["both_ready"] and event["first_turn"] == self.user.id:
            await self._start_timeout()

        await self.send(text_data=json.dumps({
            "type":       "player_ready",
            "user_id":    event["user_id"],
            "both_ready": event["both_ready"],
            "first_turn": event["first_turn"],
        }))

    async def sb_shot(self, event):
        uid = self.user.id
        is_my_turn = (event["next_turn"] == uid)

        # Сбрасываем старый таймер, запускаем новый если теперь наш ход
        await self._cancel_timeout()
        if is_my_turn and not event["game_over"]:
            await self._start_timeout()

        await self.send(text_data=json.dumps({
            "type":         "shot",
            "shooter_id":   event["shooter_id"],
            "row":          event["row"],
            "col":          event["col"],
            "hit":          event["hit"],
            "game_over":    event["game_over"],
            "winner":       event["winner"],
            "is_your_turn": is_my_turn,
            "timestamp":    event["timestamp"],
        }))

    async def sb_lobby_deleted(self, event):
        await self._cancel_timeout()
        await self.send(text_data=json.dumps({"type": "lobby_deleted"}))

    async def sb_game_ended(self, event):
        await self._cancel_timeout()
        await self.send(text_data=json.dumps({
            "type":   "game_ended",
            "winner": event.get("winner"),
            "reason": event.get("reason", ""),
        }))

    # ── Таймаут ───────────────────────────────────────────────────────────────

    async def _start_timeout(self):
        await self._cancel_timeout()
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
        """Ждём TURN_TIMEOUT секунд. Если выстрел не был сделан — поражение."""
        await asyncio.sleep(TURN_TIMEOUT)
        result = await self._forfeit_if_timeout()
        if result:
            lobby_id, winner_id = result
            group = f"seabattle_lobby_{lobby_id}"
            await self.channel_layer.group_send(group, {
                "type":   "sb_game_ended",
                "winner": winner_id,
                "reason": "timeout",
            })

    # ── DB ────────────────────────────────────────────────────────────────────

    @database_sync_to_async
    def _get_lobby(self):
        try:
            return SeaBattleLobby.objects.get(id=self.lobby_id)
        except SeaBattleLobby.DoesNotExist:
            return None

    @database_sync_to_async
    def _delete_if_empty(self, user_id):
        try:
            lobby = SeaBattleLobby.objects.get(id=self.lobby_id)
            if lobby.lobby_owner == user_id and lobby.opponent is None:
                lobby.delete()
        except SeaBattleLobby.DoesNotExist:
            pass

    @database_sync_to_async
    def _forfeit_if_timeout(self):
        """
        Если ход всё ещё за текущим пользователем и дедлайн истёк —
        засчитать ему поражение. Возвращает (lobby_id, winner_id) или None.
        """
        from django.utils import timezone
        try:
            lobby = SeaBattleLobby.objects.get(id=self.lobby_id)
        except SeaBattleLobby.DoesNotExist:
            return None

        if lobby.winner is not None or lobby.turn is None:
            return None

        if lobby.turn != self.user.id:
            return None

        if lobby.turn_deadline and timezone.now() < lobby.turn_deadline:
            return None

        winner_id = (
            lobby.opponent if lobby.lobby_owner == self.user.id else lobby.lobby_owner
        )
        lobby.winner        = winner_id
        lobby.turn          = None
        lobby.turn_deadline = None
        lobby.save()
        lobby.delete()

        return (self.lobby_id, winner_id)
