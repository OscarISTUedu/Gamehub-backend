from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView
)
from django.contrib import admin
from mainapp import views
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView

from mainapp.views import CookieTokenRefreshView, \
    GetMyAchievementsView, GetAllAchievementsView, UserTextViews, UserAvatarView

urlpatterns = [
    path('admin/', admin.site.urls),
    # API schema
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    # Swagger UI
    path('api/swagger/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),

    # Регистрация и авторизация
    path('api/register/', views.RegisterView.as_view(), name='register'),
    path('api/login/', views.LoginView.as_view(), name='login'),
    path('api/logout/', views.LogoutView.as_view(), name='logout'),
    # JWT токены
    path('api/token/refresh/', CookieTokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    # Info
    path('api/me/all/', UserTextViews.as_view(), name='my_user'),
    path('api/me/avatar/', UserAvatarView.as_view(), name='my_avatar'),
    path('api/me/achievements/', GetMyAchievementsView.as_view(), name='get_my_achievements'),
    # Achievements
    # path('api/achievement/get_all/', GetAllAchievementsView.as_view(), name='get_all_achievements'),

]