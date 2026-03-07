from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.postgres.fields import ArrayField
import uuid

class User(AbstractUser):
    username = None
    email = models.EmailField(unique=True)
    avatar = models.ImageField(upload_to='user_icons/', null=True, blank=True)
    achievements = ArrayField(models.IntegerField(), null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    class Meta:
        ordering = ['-created_at']
    def __str__(self):
        return self.email

class Achievement(models.Model):
    name = models.TextField(max_length=100)
    description = models.TextField(max_length=500)
    image = models.ImageField(upload_to='achive_icons/')
    game_id = models.IntegerField()

class Game(models.Model):
    name = models.TextField(max_length=100)
    description = models.TextField(max_length=500)
    picture = models.ImageField(upload_to='game_icons/')

class UserGameStats(models.Model):
    user_id = models.IntegerField()
    game_id = models.IntegerField()
    win = models.IntegerField(null=True, blank=True)
    lose = models.IntegerField(null=True, blank=True)

class GameLobby(models.Model):
    """Лобби для игры в крестики-нолики"""
    game_id = models.IntegerField()
    lobby_owner = models.IntegerField()
    opponent = models.IntegerField(null=True, blank=True)

    map = models.JSONField(default=list)
    turn = models.IntegerField(null=True, blank=True)
    winner = models.IntegerField(null=True, blank=True)

    # Настройки поля
    board_size = models.IntegerField(default=3)   # Размер поля (3-10)
    win_length = models.IntegerField(default=3)   # Сколько в ряд для победы

    # Дедлайн текущего хода (автопроигрыш по таймауту)
    turn_deadline = models.DateTimeField(null=True, blank=True)

    # Таймаут хода (null = игра не началась или закончена)
    turn_deadline = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'gamelobby'

    def __str__(self):
        return f"Lobby #{self.id}: owner={self.lobby_owner}, opponent={self.opponent}"

    def get_empty_map(self):
        n = self.board_size or 3
        return [[None] * n for _ in range(n)]

    def save(self, *args, **kwargs):
        if not self.map:
            self.map = self.get_empty_map()
        super().save(*args, **kwargs)


GAME_ID_SEABATTLE = 2
SEA_SIZE = 8
SHIP_LENGTHS = [4, 3, 2, 2, 1]

class SeaBattleLobby(models.Model):
    """
    Лобби для морского боя.

    Состояние каждого поля хранится как двумерный массив 8x8:
      null  — пустая клетка / не стреляли
      0     — промах (выстрел по пустой клетке)
      1     — корабль (не подбит)
      2     — попадание (подбитая клетка корабля)

    owner_ships / opponent_ships — расстановка кораблей (видна только владельцу).
    owner_shots / opponent_shots — результаты выстрелов по чужому полю.
    """
    lobby_owner   = models.IntegerField()
    opponent      = models.IntegerField(null=True, blank=True)

    # Расстановка кораблей (1 = корабль, null = пусто)
    owner_ships    = models.JSONField(default=list)
    opponent_ships = models.JSONField(default=list)

    # Выстрелы: 0 = промах, 2 = попадание, null = не стреляли
    owner_shots    = models.JSONField(default=list)   # владелец стрелял сюда (по полю opponent)
    opponent_shots = models.JSONField(default=list)   # opponent стрелял сюда (по полю owner)

    # Чья очередь (user_id)
    turn   = models.IntegerField(null=True, blank=True)
    winner = models.IntegerField(null=True, blank=True)

    # Флаги готовности (корабли расставлены)
    owner_ready    = models.BooleanField(default=False)
    opponent_ready = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'seabattlelobby'

    def empty_field(self):
        return [[None] * SEA_SIZE for _ in range(SEA_SIZE)]

    def save(self, *args, **kwargs):
        if not self.owner_ships:    self.owner_ships    = self.empty_field()
        if not self.opponent_ships: self.opponent_ships = self.empty_field()
        if not self.owner_shots:    self.owner_shots    = self.empty_field()
        if not self.opponent_shots: self.opponent_shots = self.empty_field()
        super().save(*args, **kwargs)