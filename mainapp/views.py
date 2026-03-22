import time
from datetime import timedelta
from django.db.models import Q
from rest_framework import status, permissions,  generics, mixins
from django.utils import timezone
from rest_framework.generics import GenericAPIView, ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from drf_spectacular.utils import extend_schema
from rest_framework.generics import RetrieveAPIView
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from Gamehub import settings
from .models import User, Game, Achievement, GameLobby
from .serializers import (RegisterSerializer, LoginSerializer, CustomTokenObtainPairSerializer,
                          UserAchievementSerializer, AchievementListSerializer, UserTextDataSerializer,
                          UserAvatarSerializer, GameSerializer, GameLobbySerializer)
from django.http import FileResponse, Http404
import mimetypes
import os


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
    """Выход из системы (блокировка refresh токена)"""
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


class UserTextViews(generics.RetrieveUpdateAPIView):
    """GET и PATCH для текущего пользователя"""
    serializer_class = UserTextDataSerializer
    http_method_names = ['get', 'patch']
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    def get_object(self):
        return self.request.user


class UserAvatarView(mixins.UpdateModelMixin, generics.GenericAPIView):
    """
    View для работы с аватаркой пользователя
    GET: получить сам файл изображения (FileResponse)
    POST: загрузить новую аватарку
    """
    serializer_class = UserAvatarSerializer
    http_method_names = ['get', 'post']
    parser_classes = [MultiPartParser, FormParser]

    def get_object(self):
        return self.request.user

    def get(self, request, *args, **kwargs):
        """Получить файл аватарки"""
        user = self.get_object()
        print(f"user.username={user.username}, user.avatar={user.avatar}")
        if not user.avatar:
            raise Http404("Аватар не найден")

        try:
            # Открываем файл и возвращаем его
            image_file = user.avatar.open('rb')

            # Определяем content type
            content_type, _ = mimetypes.guess_type(user.avatar.name)
            if not content_type:
                content_type = 'application/octet-stream'

            # Возвращаем файл
            return FileResponse(
                image_file,
                content_type=content_type,
                as_attachment=False,  # False для отображения в браузере
                filename=os.path.basename(user.avatar.name)
            )
        except Exception as e:
            raise Http404(f"Ошибка при загрузке аватара: {str(e)}")

    def post(self, request, *args, **kwargs):
        """Загрузить новую аватарку"""
        return self.update(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        """Обновить аватарку"""
        partial = kwargs.pop('partial', False)
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=partial)

        if serializer.is_valid():
            # Удаляем старую аватарку если она была
            if user.avatar and 'avatar' in request.FILES:
                user.avatar.delete(save=False)

            self.perform_update(serializer)

            # Возвращаем обновленные данные
            response_data = serializer.data
            if user.avatar:
                response_data['avatar_url'] = request.build_absolute_uri(user.avatar.url)

            return Response(response_data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def perform_update(self, serializer):
        serializer.save()


class GameListView(generics.ListAPIView):
    queryset = Game.objects.all()
    serializer_class = GameSerializer


class UserAchievementsView(APIView):
    def get(self, request):
        users_data = [
            {"#": 1, "nickname": "jon", "total_achievs": 10, "achieve_%": 25},
            {"#": 2, "nickname": "alice", "total_achievs": 15, "achieve_%": 60},
            {"#": 3, "nickname": "bob", "total_achievs": 8, "achieve_%": 40},
            {"#": 4, "nickname": "charlie", "total_achievs": 20, "achieve_%": 85},
            {"#": 5, "nickname": "diana", "total_achievs": 12, "achieve_%": 55},
            {"#": 6, "nickname": "eve", "total_achievs": 18, "achieve_%": 70},
            {"#": 7, "nickname": "frank", "total_achievs": 5, "achieve_%": 15},
            {"#": 8, "nickname": "grace", "total_achievs": 22, "achieve_%": 95},
            {"#": 9, "nickname": "henry", "total_achievs": 14, "achieve_%": 45},
            {"#": 10, "nickname": "isabella", "total_achievs": 9, "achieve_%": 30}
        ]
        return Response(users_data, status=status.HTTP_200_OK)
    # def get(self, request):
    #     users = User.objects.all()
    #     users_data = []
    #     for user in users:
    #         user_achievements = user.achievements if user.achievements else []
    #         total_achievs = len(user_achievements)
    #         if total_achievs > 0:
    #             achievements = Achievement.objects.filter(id__in=user_achievements)
    #             game_stats = {}
    #             for achievement in achievements:
    #                 if achievement.game_id not in game_stats:
    #                     game_stats[achievement.game_id] = {
    #                         'achieved': 0,
    #                         'total': Achievement.objects.filter(game_id=achievement.game_id).count()
    #                     }
    #                 game_stats[achievement.game_id]['achieved'] += 1
    #             if game_stats:
    #                 percentages = [
    #                     (stats['achieved'] / stats['total'] * 100)
    #                     for stats in game_stats.values()
    #                     if stats['total'] > 0
    #                 ]
    #                 achieve_percent = round(sum(percentages) / len(percentages), 2) if percentages else 0
    #             else:
    #                 achieve_percent = 0
    #         else:
    #             achieve_percent = 0
    #
    #         users_data.append({
    #             "nickname": user.username,
    #             "total_achievs": total_achievs,
    #             "achieve_%": achieve_percent
    #         })
    #     # Сортируем пользователей:
    #     # 1. По total_achievs (по убыванию)
    #     # 2. При равенстве - по achieve_% (по убыванию)
    #     sorted_users = sorted(
    #         users_data,
    #         key=lambda x: (-x['total_achievs'], -x['achieve_%'])
    #     )
    #     result = []
    #     for idx, user in enumerate(sorted_users[:10], start=1):
    #         user_with_number = {
    #             "#": idx,
    #             **user
    #         }
    #         result.append(user_with_number)
    #     return Response(result, status=status.HTTP_200_OK)
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

        if existing:
            other_id = existing.opponent if existing.lobby_owner == user_id else existing.lobby_owner
            opponent_data = None
            if other_id:
                try:
                    opp = User.objects.get(id=other_id)
                    opponent_data = {"id": opp.id, "email": opp.email}
                except User.DoesNotExist:
                    pass
            return Response({
                "status": "rejoined",
                "lobby_id": existing.id,
                "map": existing.map,
                "board_size": existing.board_size,
                "win_length": existing.win_length,
                "is_your_turn": existing.turn == user_id,
                "is_owner": existing.lobby_owner == user_id,
                "my_symbol": "X" if existing.lobby_owner == user_id else "O",
                "opponent": opponent_data,
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
            "type": "turn_made",
            "row": row,
            "col": col,
            "map": board,
            "next_turn_user_id": next_turn_user_id,
            "game_over": game_over,
            "winner": winner,
            "timestamp": timestamp,
        })

        if game_over:
            _broadcast_group(group_name, {
                "type": "game_ended",
                "winner": winner,
                "map": board,
            })
            lobby.delete()

        return Response({
            "status": "ok",
            "map": board,
            "timestamp": timestamp,
            "game_over": game_over,
            "winner": winner,
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
    DELETE /tictactoe/delete_lobby/<int:lobby_id>/
    Удалить своё лобби. Только владелец может удалить лобби.
    """
    def delete(self, request, lobby_id):
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