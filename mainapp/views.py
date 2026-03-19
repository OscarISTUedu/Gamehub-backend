from rest_framework import status, permissions, generics, mixins
from rest_framework.generics import GenericAPIView, ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from drf_spectacular.utils import extend_schema
from rest_framework.generics import RetrieveAPIView
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from Gamehub import settings
from .models import User, Game, Achievement
from .serializers import (RegisterSerializer, LoginSerializer, CustomTokenObtainPairSerializer,
                          UserAchievementSerializer, AchievementListSerializer, UserTextDataSerializer,
                          UserAvatarSerializer, GameSerializer)
from django.http import FileResponse, Http404
import mimetypes
import os


class RegisterView(GenericAPIView):
    """Регистрация нового пользователя"""
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        # Создаем токены для нового пользователя
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
    """Авторизация пользователя"""
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
            return Response(
                {"error": "Required refresh token"}, status=status.HTTP_400_BAD_REQUEST
            )
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception as e:
            return Response(
                {"error": f"Invalid Refresh token"}, status=status.HTTP_400_BAD_REQUEST
            )
        return Response(status=status.HTTP_200_OK)


class CustomTokenObtainPairView(TokenObtainPairView):
    """Кастомное представление для получения JWT токенов"""
    serializer_class = CustomTokenObtainPairSerializer


class CookieTokenRefreshView(TokenRefreshView):
    @extend_schema(
        request=None,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "access": {
                        "type": "string",
                        "description": "Access token",
                    }
                },
            }
        },
    )
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
        content = {
            'email': request.user.email,
        }
        return Response(content)

class GetMyRegistrationDateView(APIView):
    def get(self, request):
        content = {
            'created_at': request.user.created_at,
        }
        return Response(content)

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
        users = User.objects.all()
        users_data = []
        for user in users:
            user_achievements = user.achievements if user.achievements else []
            total_achievs = len(user_achievements)
            if total_achievs > 0:
                achievements = Achievement.objects.filter(id__in=user_achievements)
                game_stats = {}
                for achievement in achievements:
                    if achievement.game_id not in game_stats:
                        game_stats[achievement.game_id] = {
                            'achieved': 0,
                            'total': Achievement.objects.filter(game_id=achievement.game_id).count()
                        }
                    game_stats[achievement.game_id]['achieved'] += 1
                if game_stats:
                    percentages = [
                        (stats['achieved'] / stats['total'] * 100)
                        for stats in game_stats.values()
                        if stats['total'] > 0
                    ]
                    achieve_percent = round(sum(percentages) / len(percentages), 2) if percentages else 0
                else:
                    achieve_percent = 0
            else:
                achieve_percent = 0

            users_data.append({
                "nickname": user.username,
                "total_achievs": total_achievs,
                "achieve_%": achieve_percent
            })
        # Сортируем пользователей:
        # 1. По total_achievs (по убыванию)
        # 2. При равенстве - по achieve_% (по убыванию)
        sorted_users = sorted(
            users_data,
            key=lambda x: (-x['total_achievs'], -x['achieve_%'])
        )
        result = []
        for idx, user in enumerate(sorted_users[:10], start=1):
            user_with_number = {
                "#": idx,
                **user
            }
            result.append(user_with_number)
        return Response(result, status=status.HTTP_200_OK)