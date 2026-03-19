import time
from datetime import timedelta
from datetime import timedelta
from django.utils import timezone
from django.db.models import Q
from rest_framework import status, permissions
from django.utils import timezone
from rest_framework.generics import GenericAPIView, ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from drf_spectacular.utils import extend_schema
from rest_framework.generics import RetrieveAPIView
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from Gamehub import settings
from .models import User, GameLobby
from .serializers import (RegisterSerializer, LoginSerializer, CustomTokenObtainPairSerializer,
                          UserAchievementSerializer, AchievementListSerializer, GameLobbySerializer)

class RegisterView(GenericAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        data = {}
        refresh.payload.update({"user_id": user.id})
        data["access"] = str(refresh.access_token)
        response = Response(data)
        response.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE"],
            value=str(refresh),
            max_age=int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()),
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )
        return response


class LoginView(GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)
        data = {}
        refresh.payload.update({"user_id": user.id})
        data["access"] = str(refresh.access_token)
        response = Response(data)
        response.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE"],
            value=str(refresh),
            max_age=int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()),
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )
        return response


class LogoutView(GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    @extend_schema(request=None, responses=None)
    def post(self, request):
        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT["AUTH_COOKIE"])
        if not refresh_token:
            return Response({"error": "Required refresh token"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception:
            return Response({"error": "Invalid Refresh token"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_200_OK)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class CookieTokenRefreshView(TokenRefreshView):
    @extend_schema(request=None, responses={200: {"type": "object", "properties": {"access": {"type": "string"}}}})
    def post(self, request, *args, **kwargs):
        if settings.SIMPLE_JWT["AUTH_COOKIE"] in request.COOKIES:
            refresh_token = request.COOKIES.get(settings.SIMPLE_JWT["AUTH_COOKIE"])
            request._full_data = request.data.copy()
            request._full_data['refresh'] = refresh_token
            request._data = request._full_data
        response = super().post(request, *args, **kwargs)
        if response.status_code == status.HTTP_200_OK:
            if 'refresh' in response.data:
                response.set_cookie(
                    key=settings.SIMPLE_JWT["AUTH_COOKIE"],
                    value=response.data['refresh'],
                    max_age=int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()),
                    secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
                    httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
                    samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
                )
                response.data.pop('refresh')
        return response


class AuthTest(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        return Response({"status": "authorized"})


class GetMyEmailView(APIView):
    def get(self, request):
        return Response({'email': request.user.email})

class GetMyRegistrationDateView(APIView):
    def get(self, request):
        return Response({'created_at': request.user.created_at})

class GetMyAchievementsView(RetrieveAPIView):
    serializer_class = UserAchievementSerializer
    def get_object(self):
        return self.request.user

class GetAllAchievementsView(ListAPIView):
    serializer_class = AchievementListSerializer


GAME_ID_TICTACTOE = 1
channel_layer = get_channel_layer()


def _broadcast_group(group_name: str, message: dict):
    async_to_sync(channel_layer.group_send)(group_name, message)



def _check_win(board: list, player_id: int, win_length: int) -> bool:
    """Проверить победу на доске произвольного размера."""
    size = len(board)
    # ряды
    for r in range(size):
        for c in range(size - win_length + 1):
            if all(board[r][c + k] == player_id for k in range(win_length)):
                return True
    # столбцы
    for c in range(size):
        for r in range(size - win_length + 1):
            if all(board[r + k][c] == player_id for k in range(win_length)):
                return True
    # диагональ \
    for r in range(size - win_length + 1):
        for c in range(size - win_length + 1):
            if all(board[r + k][c + k] == player_id for k in range(win_length)):
                return True
    # диагональ /
    for r in range(size - win_length + 1):
        for c in range(win_length - 1, size):
            if all(board[r + k][c - k] == player_id for k in range(win_length)):
                return True
    return False


def _check_draw(board: list) -> bool:
    return all(cell is not None for row in board for cell in row)


class GameStartView(APIView):
    """
    POST /tictactoe/game_start/
    Body (опционально): { "board_size": 3-10, "win_length": 3-10 }

    Создатель лобби задаёт настройки. Противник принимает настройки создателя.
    Поиск совместимого лобби: только лобби с такими же board_size и win_length.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        user_id = user.id

        # Настройки из запроса (только для создателя, при поиске — игнорируются)
        board_size = int(request.data.get("board_size", 3))
        win_length = int(request.data.get("win_length", 3))

        # Валидация
        board_size = max(3, min(10, board_size))
        win_length = max(3, min(board_size, win_length))

        # Шаг 2: Поиск существующих игр где я участник
        existing = GameLobby.objects.filter(
            game_id=GAME_ID_TICTACTOE
        ).filter(
            Q(lobby_owner=user_id) | Q(opponent=user_id)
        ).first()

        # Удаляем завершённые лобби где я участник
        GameLobby.objects.filter(
            game_id=GAME_ID_TICTACTOE
        ).filter(
            Q(lobby_owner=user_id) | Q(opponent=user_id),
            winner__isnull=False,
        ).delete()

        if existing and existing.winner is None:
            other_id = existing.opponent if existing.lobby_owner == user_id else existing.lobby_owner
            opponent_data = None
            if other_id:
                try:
                    opp = User.objects.get(id=other_id)
                    opponent_data = {"id": opp.id, "email": opp.email}
                except User.DoesNotExist:
                    pass

            turn_deadline_ts = None
            if existing.turn_deadline:
                turn_deadline_ts = int(existing.turn_deadline.timestamp())

            return Response({
                "status":        "rejoined",
                "lobby_id":      existing.id,
                "map":           existing.map,
                "board_size":    existing.board_size,
                "win_length":    existing.win_length,
                "is_your_turn":  existing.turn == user_id,
                "is_owner":      existing.lobby_owner == user_id,
                "my_symbol":     "X" if existing.lobby_owner == user_id else "O",
                "opponent":      opponent_data,
                "turn_deadline": turn_deadline_ts,
            })

        # Шаг 3: Поиск открытого лобби с совпадающими настройками
        open_lobby = GameLobby.objects.filter(
            game_id=GAME_ID_TICTACTOE,
            opponent__isnull=True,
            board_size=board_size,
            win_length=win_length,
        ).exclude(lobby_owner=user_id).first()

        if open_lobby:
            # Присоединяемся
            open_lobby.opponent = user_id
            open_lobby.turn = open_lobby.lobby_owner
            open_lobby.turn_deadline = timezone.now() + timedelta(seconds=120)
            open_lobby.save()

            try:
                owner = User.objects.get(id=open_lobby.lobby_owner)
                owner_data = {"id": owner.id, "email": owner.email}
            except User.DoesNotExist:
                owner_data = None

            group_name = f"tictactoe_lobby_{open_lobby.id}"
            _broadcast_group(group_name, {
                "type": "opponent_found",
                "opponent": {"id": user_id, "email": user.email},
                "is_your_turn": True,
                "map": open_lobby.map,
                "board_size": open_lobby.board_size,
                "win_length": open_lobby.win_length,
                "my_symbol": "X",
            })

            return Response({
                "status": "joined",
                "lobby_id": open_lobby.id,
                "map": open_lobby.map,
                "board_size": open_lobby.board_size,
                "win_length": open_lobby.win_length,
                "is_your_turn": False,
                "is_owner": False,
                "my_symbol": "O",
                "turn_started_at": int(open_lobby.updated_at.timestamp()),
                "opponent": owner_data,
            })

        # Шаг 4: Создание нового лобби с заданными настройками
        empty_map = [[None] * board_size for _ in range(board_size)]
        lobby = GameLobby.objects.create(
            game_id=GAME_ID_TICTACTOE,
            lobby_owner=user_id,
            opponent=None,
            map=empty_map,
            turn=None,
            board_size=board_size,
            win_length=win_length,
        )

        return Response({
            "status": "created",
            "lobby_id": lobby.id,
            "map": lobby.map,
            "board_size": lobby.board_size,
            "win_length": lobby.win_length,
            "is_your_turn": None,
            "is_owner": True,
            "opponent": None,
        }, status=status.HTTP_201_CREATED)


class MakeTurnView(APIView):
    """POST /tictactoe/make_turn/"""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data
        lobby_id = data.get("lobby_id")
        row = data.get("row")
        col = data.get("col")

        if row is None or col is None or lobby_id is None:
            return Response({"error": "Необходимы lobby_id, row и col"}, status=400)

        try:
            lobby = GameLobby.objects.get(id=lobby_id)
        except GameLobby.DoesNotExist:
            return Response({"error": "Лобби не найдено"}, status=404)

        if lobby.turn != user.id:
            return Response({"error": "Сейчас не ваш ход"}, status=403)

        # ── Проверка дедлайна ─────────────────────────────────────────────────
        if lobby.turn_deadline and timezone.now() > lobby.turn_deadline:
            # Время истекло — засчитываем поражение текущему игроку
            winner_id = (
                lobby.opponent if lobby.lobby_owner == user.id else lobby.lobby_owner
            )
            lobby.winner = winner_id
            lobby.turn = None
            lobby.turn_deadline = None
            lobby.save()

            group_name = f"tictactoe_lobby_{lobby_id}"
            _broadcast_group(group_name, {
                "type":   "game_ended",
                "winner": winner_id,
                "map":    lobby.map,
                "reason": "timeout",
            })
            lobby.delete()

            return Response({"error": "Время хода истекло"}, status=403)

        # ── Обычный ход ───────────────────────────────────────────────────────
        board = lobby.map
        if board[row][col] is not None:
            return Response({"error": "Ячейка уже занята"}, status=400)

        board[row][col] = user.id
        lobby.map = board

        win_length = lobby.win_length
        game_over = None
        winner = None
        if _check_win(board, user.id, win_length):
            game_over = True
            winner = user.id
        elif _check_draw(board):
            game_over = True
            winner = 0

        other_id = lobby.opponent if lobby.lobby_owner == user.id else lobby.lobby_owner

        if not game_over:
            lobby.turn = other_id
            lobby.turn_deadline = timezone.now() + timedelta(seconds=120)
        else:
            lobby.turn = None
            lobby.turn_deadline = None

        lobby.save()

        timestamp = int(time.time())
        next_turn_user_id = other_id if not game_over else None
        group_name = f"tictactoe_lobby_{lobby_id}"
        _broadcast_group(group_name, {
            "type":             "turn_made",
            "row":              row,
            "col":              col,
            "map":              board,
            "next_turn_user_id": next_turn_user_id,
            "game_over":        game_over,
            "winner":           winner,
            "timestamp":        timestamp,
        })

        if game_over:
            _broadcast_group(group_name, {
                "type":   "game_ended",
                "winner": winner,
                "map":    board,
            })
            lobby.delete()

        return Response({
            "status":    "ok",
            "map":       board,
            "timestamp": timestamp,
            "game_over": game_over,
            "winner":    winner,
        })


class GetOpponentInfoView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        lobby_id = request.query_params.get("lobby_id")
        try:
            lobby = GameLobby.objects.get(id=lobby_id)
        except GameLobby.DoesNotExist:
            return Response({"error": "Лобби не найдено"}, status=404)

        user_id = request.user.id
        other_id = lobby.opponent if lobby.lobby_owner == user_id else lobby.lobby_owner

        if not other_id:
            return Response({"opponent": None})

        try:
            opp = User.objects.get(id=other_id)
            return Response({"opponent": {
                "id": opp.id,
                "email": opp.email,
                "avatar": opp.avatar.url if opp.avatar else None,
            }})
        except User.DoesNotExist:
            return Response({"opponent": None})


class GetCurrentUserView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "id": user.id,
            "email": user.email,
            "avatar": user.avatar.url if user.avatar else None,
            "created_at": user.created_at,
        })


class DeleteLobbyView(APIView):
    """
    DELETE /tictactoe/delete_lobby/
    Удалить своё лобби. Только владелец может удалить лобби.
    Body: { "lobby_id": int }
    """
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request):
        lobby_id = request.data.get("lobby_id")
        if not lobby_id:
            return Response({"error": "Необходим lobby_id"}, status=400)

        try:
            lobby = GameLobby.objects.get(id=lobby_id)
        except GameLobby.DoesNotExist:
            return Response({"error": "Лобби не найдено"}, status=404)

        if lobby.lobby_owner != request.user.id:
            return Response({"error": "Только владелец может удалить лобби"}, status=403)

        # Уведомить противника если он есть
        if lobby.opponent:
            group_name = f"tictactoe_lobby_{lobby_id}"
            _broadcast_group(group_name, {
                "type": "game_ended",
                "winner": None,
                "map": lobby.map,
            })

        lobby.delete()
        return Response({"status": "deleted"})