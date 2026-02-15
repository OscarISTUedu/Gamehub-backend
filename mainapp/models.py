from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.postgres.fields import ArrayField

class User(AbstractUser):
    username = None
    email = models.EmailField(unique=True)
    avatar = models.ImageField(upload_to='user_icons/', null=True, blank=True)
    achievements = ArrayField(models.IntegerField(), null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    USERNAME_FIELD = 'email'  # Используем email для аутентификации
    REQUIRED_FIELDS = []  # Убираем обязательные поля кроме email и password
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