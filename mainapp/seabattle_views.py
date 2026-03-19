"""
seabattle_views.py — HTTP-эндпоинты для морского боя.
"""
import time
from datetime import timedelta
from django.db.models import Q
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from mainapp.models import User, SeaBattleLobby, SEA_SIZE, SHIP_LENGTHS

channel_layer = get_channel_layer()

TURN_TIMEOUT = 120  # секунд


def _broadcast(group: str, message: dict):
    async_to_sync(channel_layer.group_send)(group, message)


def _group(lobby_id: int) -> str:
    return f"seabattle_lobby_{lobby_id}"


def _empty():
    return [[None] * SEA_SIZE for _ in range(SEA_SIZE)]


def _validate_ships(ships: list) -> bool:
    """Проверить что расстановка корректна."""
    if len(ships) != SEA_SIZE or any(len(r) != SEA_SIZE for r in ships):
        return False
    visited = [[False] * SEA_SIZE for _ in range(SEA_SIZE)]
    found = []
    for r in range(SEA_SIZE):
        for c in range(SEA_SIZE):
            if ships[r][c] == 1 and not visited[r][c]:
                cells = []
                queue = [(r, c)]
                while queue:
                    cr, cc = queue.pop()
                    if visited[cr][cc]: continue
                    visited[cr][cc] = True
                    cells.append((cr, cc))
                    for dr, dc in [(-1,0),(1,0),(0,-1),(0,1)]:
                        nr, nc = cr+dr, cc+dc
                        if 0 <= nr < SEA_SIZE and 0 <= nc < SEA_SIZE and ships[nr][nc] == 1 and not visited[nr][nc]:
                            queue.append((nr, nc))
                found.append(len(cells))
    found.sort(reverse=True)
    expected = sorted(SHIP_LENGTHS, reverse=True)
    if found != expected:
        return False
    for r in range(SEA_SIZE):
        for c in range(SEA_SIZE):
            if ships[r][c] == 1:
                for dr in [-1, 0, 1]:
                    for dc in [-1, 0, 1]:
                        if dr == 0 and dc == 0: continue
                        nr, nc = r+dr, c+dc
                        if 0 <= nr < SEA_SIZE and 0 <= nc < SEA_SIZE:
                            if ships[nr][nc] == 1:
                                if dr != 0 and dc != 0:
                                    return False
    return True


def _check_win(ships: list, shots: list) -> bool:
    for r in range(SEA_SIZE):
        for c in range(SEA_SIZE):
            if ships[r][c] == 1 and shots[r][c] != 2:
                return False
    return True


def _user_info(user_id: int) -> dict | None:
    try:
        u = User.objects.get(id=user_id)
        return {"id": u.id, "email": u.email, "avatar": u.avatar.url if u.avatar else None}
    except User.DoesNotExist:
        return None


def _lobby_state(lobby: SeaBattleLobby, user_id: int) -> dict:
    is_owner   = lobby.lobby_owner == user_id
    my_ships   = lobby.owner_ships    if is_owner else lobby.opponent_ships
    my_shots   = lobby.owner_shots    if is_owner else lobby.opponent_shots
    enemy_shots = lobby.opponent_shots if is_owner else lobby.owner_shots
    my_ready   = lobby.owner_ready    if is_owner else lobby.opponent_ready
    enemy_ready = lobby.opponent_ready if is_owner else lobby.owner_ready
    other_id   = lobby.opponent       if is_owner else lobby.lobby_owner

    enemy_view = [[None] * SEA_SIZE for _ in range(SEA_SIZE)]
    for r in range(SEA_SIZE):
        for c in range(SEA_SIZE):
            if my_shots[r][c] is not None:
                enemy_view[r][c] = my_shots[r][c]

    return {
        "lobby_id":     lobby.id,
        "is_owner":     is_owner,
        "my_ships":     my_ships,
        "my_shots":     enemy_shots,
        "enemy_view":   enemy_view,
        "my_ready":     my_ready,
        "enemy_ready":  enemy_ready,
        "is_your_turn": lobby.turn == user_id,
        "opponent":     _user_info(other_id) if other_id else None,
        "winner":       lobby.winner,
    }


# ─── Views ────────────────────────────────────────────────────────────────────

class SBGameStartView(APIView):
    """POST /seabattle/game_start/"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        uid  = user.id

        # Уже участвую в игре?
        existing = SeaBattleLobby.objects.filter(
            Q(lobby_owner=uid) | Q(opponent=uid),
            winner__isnull=True,
        ).first()
        if existing:
            turn_deadline_ts = None
            if existing.turn_deadline:
                turn_deadline_ts = int(existing.turn_deadline.timestamp())

            return Response({
                "status": "rejoined",
                **_lobby_state(existing, uid),
                "turn_deadline": turn_deadline_ts,
            })

        # Открытое лобби без противника
        open_lobby = SeaBattleLobby.objects.filter(
            opponent__isnull=True,
            winner__isnull=True,
        ).exclude(lobby_owner=uid).first()

        if open_lobby:
            open_lobby.opponent = uid
            open_lobby.save()

            _broadcast(_group(open_lobby.id), {
                "type": "sb_opponent_joined",
                "opponent": _user_info(uid),
            })

            return Response({
                "status": "joined",
                **_lobby_state(open_lobby, uid),
                "turn_deadline": None,
            })

        # Создать новое лобби
        lobby = SeaBattleLobby.objects.create(lobby_owner=uid)
        return Response({
            "status": "created",
            **_lobby_state(lobby, uid),
            "turn_deadline": None,
        }, status=status.HTTP_201_CREATED)


class SBPlaceShipsView(APIView):
    """POST /seabattle/place_ships/"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        uid      = request.user.id
        lobby_id = request.data.get("lobby_id")
        ships    = request.data.get("ships")

        if not lobby_id or ships is None:
            return Response({"error": "Нужны lobby_id и ships"}, status=400)

        if not _validate_ships(ships):
            return Response({"error": "Неверная расстановка кораблей"}, status=400)

        try:
            lobby = SeaBattleLobby.objects.get(id=lobby_id)
        except SeaBattleLobby.DoesNotExist:
            return Response({"error": "Лобби не найдено"}, status=404)

        if lobby.lobby_owner == uid:
            lobby.owner_ships = ships
            lobby.owner_ready = True
        elif lobby.opponent == uid:
            lobby.opponent_ships = ships
            lobby.opponent_ready = True
        else:
            return Response({"error": "Вы не участник этого лобби"}, status=403)

        both_ready = lobby.owner_ready and lobby.opponent_ready

        # Оба готовы — начинаем, первый ход у владельца, ставим дедлайн
        if both_ready and lobby.turn is None:
            lobby.turn = lobby.lobby_owner
            lobby.turn_deadline = timezone.now() + timedelta(seconds=TURN_TIMEOUT)

        lobby.save()

        _broadcast(_group(lobby_id), {
            "type":       "sb_player_ready",
            "user_id":    uid,
            "both_ready": both_ready,
            "first_turn": lobby.turn,
        })

        return Response({
            "status":       "ok",
            "both_ready":   both_ready,
            "is_your_turn": lobby.turn == uid,
        })


class SBShootView(APIView):
    """POST /seabattle/shoot/"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        uid      = request.user.id
        lobby_id = request.data.get("lobby_id")
        row      = request.data.get("row")
        col      = request.data.get("col")

        if lobby_id is None or row is None or col is None:
            return Response({"error": "Нужны lobby_id, row, col"}, status=400)

        try:
            lobby = SeaBattleLobby.objects.get(id=lobby_id)
        except SeaBattleLobby.DoesNotExist:
            return Response({"error": "Лобби не найдено"}, status=404)

        if lobby.turn != uid:
            return Response({"error": "Сейчас не ваш ход"}, status=403)

        if not lobby.both_ready:
            return Response({"error": "Оба игрока должны расставить корабли"}, status=400)

        # ── Проверка дедлайна ─────────────────────────────────────────────
        if lobby.turn_deadline and timezone.now() > lobby.turn_deadline:
            winner_id = lobby.opponent if lobby.lobby_owner == uid else lobby.lobby_owner
            lobby.winner        = winner_id
            lobby.turn          = None
            lobby.turn_deadline = None
            lobby.save()

            _broadcast(_group(lobby_id), {
                "type":   "sb_game_ended",
                "winner": winner_id,
                "reason": "timeout",
            })
            lobby.delete()
            return Response({"error": "Время хода истекло"}, status=403)

        is_owner    = lobby.lobby_owner == uid
        my_shots    = lobby.owner_shots    if is_owner else lobby.opponent_shots
        enemy_ships = lobby.opponent_ships if is_owner else lobby.owner_ships
        other_id    = lobby.opponent       if is_owner else lobby.lobby_owner

        if my_shots[row][col] is not None:
            return Response({"error": "Уже стреляли сюда"}, status=400)

        hit = enemy_ships[row][col] == 1
        my_shots[row][col] = 2 if hit else 0

        if is_owner:
            lobby.owner_shots = my_shots
        else:
            lobby.opponent_shots = my_shots

        game_over = False
        winner    = None
        if hit and _check_win(enemy_ships, my_shots):
            game_over    = True
            winner       = uid
            lobby.winner = uid
            lobby.turn   = None
            lobby.turn_deadline = None
        elif not hit:
            # Промах — ход переходит, обновляем дедлайн
            lobby.turn          = other_id
            lobby.turn_deadline = timezone.now() + timedelta(seconds=TURN_TIMEOUT)

        lobby.save()

        timestamp = int(time.time())

        _broadcast(_group(lobby_id), {
            "type":       "sb_shot",
            "shooter_id": uid,
            "row":        row,
            "col":        col,
            "hit":        hit,
            "game_over":  game_over,
            "winner":     winner,
            "next_turn":  lobby.turn,
            "timestamp":  timestamp,
        })

        if game_over:
            lobby.delete()

        return Response({
            "status":       "ok",
            "hit":          hit,
            "game_over":    game_over,
            "winner":       winner,
            "is_your_turn": lobby.turn == uid,
            "timestamp":    timestamp,
        })


class SBDeleteLobbyView(APIView):
    """DELETE /seabattle/delete_lobby/ — удалить пустое лобби (только владелец)."""
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request):
        lobby_id = request.data.get("lobby_id")
        if not lobby_id:
            return Response({"error": "Нужен lobby_id"}, status=400)

        try:
            lobby = SeaBattleLobby.objects.get(id=lobby_id)
        except SeaBattleLobby.DoesNotExist:
            return Response({"error": "Лобби не найдено"}, status=404)

        if lobby.lobby_owner != request.user.id:
            return Response({"error": "Только владелец может удалить лобби"}, status=403)

        if lobby.opponent:
            _broadcast(_group(lobby_id), {"type": "sb_lobby_deleted"})

        lobby.delete()
        return Response({"status": "deleted"})


class SBLeaveLobbyView(APIView):
    """
    POST /seabattle/leave_lobby/
    Body: { "lobby_id": int }

    Доступно любому участнику. При выходе уведомляет второго игрока
    через WS и удаляет лобби.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        lobby_id = request.data.get("lobby_id")
        if not lobby_id:
            return Response({"error": "Необходим lobby_id"}, status=400)

        try:
            lobby = SeaBattleLobby.objects.get(id=lobby_id)
        except SeaBattleLobby.DoesNotExist:
            return Response({"status": "already_deleted"})

        # Уведомляем второго игрока если он есть
        if lobby.opponent:
            _broadcast(_group(lobby_id), {"type": "sb_lobby_deleted"})

        lobby.delete()
        return Response({"status": "ok"})


class SBGetCurrentUserView(APIView):
    """GET /seabattle/me/"""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        u = request.user
        return Response({
            "id":         u.id,
            "email":      u.email,
            "avatar":     u.avatar.url if u.avatar else None,
            "created_at": u.created_at,
        })
