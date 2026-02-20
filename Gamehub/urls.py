from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView
)
from mainapp import views
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView

from mainapp.views import AuthTest, CookieTokenRefreshView, GetMyEmailView, GetMyRegistrationDateView, \
    GetMyAchievementsView, GetAllAchievementsView

urlpatterns = [
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
    path('api/info/me/email/', GetMyEmailView.as_view(), name='get_my_email'),
    path('api/info/me/reg_date/', GetMyRegistrationDateView.as_view(), name='get_my_reg_date'),
    path('api/info/me/achievements/', GetMyAchievementsView.as_view(), name='get_my_achievements'),
    # Set
    # path('api/achievement/get_all/', GetAllAchievementsView.as_view(), name='get_all_achievements'),

]