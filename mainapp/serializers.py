from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import User, Achievement, Game


class RegisterSerializer(serializers.ModelSerializer):
    """Сериализатор для регистрации"""
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    username = serializers.CharField(
        required=True,
        allow_blank=False,
        max_length=20
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password]
    )
    class Meta:
        model = User
        fields = ('email', 'username', 'password')

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data['email'],
            username=validated_data['username'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    """Сериализатор для логина"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'),email=email, password=password)
            if not user:
                raise serializers.ValidationError(
                    "Неверный email или пароль",
                    code='authorization'
                )
        else:
            raise serializers.ValidationError("Необходимо указать email и пароль")
        data['user'] = user
        return data


class UserAvatarSerializer(serializers.ModelSerializer):
    """Сериализатор для аватарки пользователя"""
    class Meta:
        model = User
        fields = ('id', 'avatar')
        read_only_fields = ('id',)

    def update(self, instance, validated_data):
         # Обновляем поля
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

class UserTextDataSerializer(serializers.ModelSerializer):
    """Сериализатор для профиля пользователя"""
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'created_at', 'updated_at', 'description')
        read_only_fields = ('id', 'created_at', 'updated_at', 'email', 'password')

    def update(self, instance, validated_data):
         # Обновляем поля
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Кастомный сериализатор для JWT токенов"""
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Добавляем кастомные поля в токен
        token['username'] = user.username
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        # Добавляем дополнительные данные в ответ
        data['user'] = {
            'id': self.user.id,
            'username': self.user.username,
        }
        return data


class AchievementSerializer(serializers.ModelSerializer):
    game = serializers.SerializerMethodField()
    class Meta:
        model = Achievement
        fields = ['name', 'description', 'image', 'game']
        read_only_fields = ['id']

    def get_game(self, obj):
        try:
            game = Game.objects.only('name').get(id=obj.game_id)
            return game.name
        except Game.DoesNotExist:
            return None


class UserAchievementSerializer(serializers.ModelSerializer):
    achievements = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = ['achievements']

    def get_achievements(self, obj):
        if not obj.achievements:
            return []
        achievements = Achievement.objects.filter(id__in=obj.achievements)
        return AchievementSerializer(achievements, many=True).data


class AchievementListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Achievement
        fields = ['name', 'description', 'image', 'game_id']
        list_serializer_class = serializers.ListSerializer