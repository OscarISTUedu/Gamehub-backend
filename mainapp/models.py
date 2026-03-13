from datetime import datetime

from django.contrib.auth.base_user import BaseUserManager
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.postgres.fields import ArrayField

def user_avatar_path(instance, filename):
    # Генерирует путь: user_avatars/user_{id}/avatar_{timestamp}.ext
    ext = filename.split('.')[-1]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f'user_avatars/user_{instance.id}/avatar_{timestamp}.{ext}'

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email должен быть указан')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        # Для суперпользователя можно сгенерировать username автоматически
        if 'username' not in extra_fields or not extra_fields['username']:
            extra_fields['username'] = email.split('@')[0]

        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    username = models.CharField(max_length=20)
    email = models.EmailField(unique=True)
    avatar = models.ImageField(upload_to=user_avatar_path, null=True, blank=True)
    achievements = ArrayField(models.IntegerField(), null=True, blank=True)
    description = models.CharField(max_length=200, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    class Meta:
        ordering = ['-created_at']

    objects = UserManager()
    def __str__(self):
        return self.username

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