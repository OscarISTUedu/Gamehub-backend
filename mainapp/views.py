from rest_framework import status, permissions
from rest_framework.generics import GenericAPIView, ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from drf_spectacular.utils import extend_schema
from rest_framework.generics import RetrieveAPIView

from Gamehub import settings
from .models import User
from .serializers import (RegisterSerializer, LoginSerializer, CustomTokenObtainPairSerializer,
                          UserAchievementSerializer, AchievementListSerializer)



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
    permission_classes = [permissions.IsAuthenticated]
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


class AuthTest(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        data = {"status": "authorized"}
        response = Response(data)
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

