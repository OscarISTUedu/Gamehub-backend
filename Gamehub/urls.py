from django.urls import path
from rest_framework_simplejwt.views import TokenVerifyView
from django.contrib import admin
from mainapp import views
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from mainapp.seabattle_views import (
    SBGameStartView, SBPlaceShipsView, SBShootView, SBDeleteLobbyView, SBGetCurrentUserView,
)
from mainapp.views import (CookieTokenRefreshView, GetMyAchievementsView, UserTextViews, UserAvatarView,
                           GameStartView, MakeTurnView, GetCurrentUserView, GetOpponentInfoView, DeleteLobbyView,
                           GameListView, UserAchievementsView)

urlpatterns = [
    path('api/admin/', admin.site.urls),
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
    path('api/info/me/achievements/', GetMyAchievementsView.as_view(), name='get_my_achievements'),
    # Games
    path('api/game/all/', GameListView.as_view(), name='get_all_games'),
    # Leader Table
    path('api/leader_table/', UserAchievementsView.as_view(), name='get_leader_table'),
    # ── TicTacToe ──────────────────────────────────────────────────────────
    path('tictactoe/game_start/', GameStartView.as_view(), name='tictactoe_game_start'),
    path('tictactoe/make_turn/', MakeTurnView.as_view(), name='tictactoe_make_turn'),
    path('tictactoe/me/', GetCurrentUserView.as_view(), name='tictactoe_me'),
    path('tictactoe/opponent_info/', GetOpponentInfoView.as_view(), name='tictactoe_opponent_info'),
    path('tictactoe/delete_lobby/', DeleteLobbyView.as_view(), name='tictactoe_delete_lobby'),

    # ── SeaBattle ──────────────────────────────────────────────────────────
    path('seabattle/game_start/', SBGameStartView.as_view(), name='sb_game_start'),
    path('seabattle/place_ships/', SBPlaceShipsView.as_view(), name='sb_place_ships'),
    path('seabattle/shoot/', SBShootView.as_view(), name='sb_shoot'),
    path('seabattle/delete_lobby/', SBDeleteLobbyView.as_view(), name='sb_delete_lobby'),
    path('seabattle/me/', SBGetCurrentUserView.as_view(), name='sb_me'),

]