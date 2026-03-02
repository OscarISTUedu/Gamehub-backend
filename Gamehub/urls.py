from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
from mainapp import views
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from mainapp.views import (
    AuthTest, CookieTokenRefreshView, GetMyEmailView, GetMyRegistrationDateView,
    GetMyAchievementsView, GetAllAchievementsView,
    GameStartView, MakeTurnView, GetOpponentInfoView, GetCurrentUserView, DeleteLobbyView,
)
from mainapp.seabattle_views import (
    SBGameStartView, SBPlaceShipsView, SBShootView, SBDeleteLobbyView, SBGetCurrentUserView,
)

urlpatterns = [
    path('api/schema/',   SpectacularAPIView.as_view(),   name='schema'),
    path('api/swagger/',  SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),

    path('api/register/', views.RegisterView.as_view(),   name='register'),
    path('api/login/',    views.LoginView.as_view(),       name='login'),
    path('api/logout/',   views.LogoutView.as_view(),      name='logout'),

    path('api/token/refresh/', CookieTokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/',  TokenVerifyView.as_view(),         name='token_verify'),

    path('api/info/me/email/',        GetMyEmailView.as_view(),          name='get_my_email'),
    path('api/info/me/reg_date/',     GetMyRegistrationDateView.as_view(), name='get_my_reg_date'),
    path('api/info/me/achievements/', GetMyAchievementsView.as_view(),   name='get_my_achievements'),

    # ── TicTacToe ──────────────────────────────────────────────────────────
    path('tictactoe/game_start/',    GameStartView.as_view(),    name='tictactoe_game_start'),
    path('tictactoe/make_turn/',     MakeTurnView.as_view(),     name='tictactoe_make_turn'),
    path('tictactoe/me/',            GetCurrentUserView.as_view(), name='tictactoe_me'),
    path('tictactoe/opponent_info/', GetOpponentInfoView.as_view(), name='tictactoe_opponent_info'),
    path('tictactoe/delete_lobby/',  DeleteLobbyView.as_view(),  name='tictactoe_delete_lobby'),

    # ── SeaBattle ──────────────────────────────────────────────────────────
    path('seabattle/game_start/',   SBGameStartView.as_view(),   name='sb_game_start'),
    path('seabattle/place_ships/',  SBPlaceShipsView.as_view(),  name='sb_place_ships'),
    path('seabattle/shoot/',        SBShootView.as_view(),       name='sb_shoot'),
    path('seabattle/delete_lobby/', SBDeleteLobbyView.as_view(), name='sb_delete_lobby'),
    path('seabattle/me/',           SBGetCurrentUserView.as_view(), name='sb_me'),
]