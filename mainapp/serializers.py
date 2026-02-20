from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import User, Achievement

class RegisterSerializer(serializers.ModelSerializer):
    """Сериализатор для регистрации"""
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password]
    )
    class Meta:
        model = User
        fields = ('email', 'password')

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data['email'],
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


class UserSerializer(serializers.ModelSerializer):
    """Сериализатор для профиля пользователя"""
    class Meta:
        model = User
        fields = ('id', 'email', 'avatar', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Кастомный сериализатор для JWT токенов"""
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Добавляем кастомные поля в токен
        token['email'] = user.email
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        # Добавляем дополнительные данные в ответ
        data['user'] = {
            'id': self.user.id,
            'email': self.user.email,
        }
        return data


class AchievementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Achievement
        fields = ['name', 'description', 'image', 'game_id']
        read_only_fields = ['id']


class UserAchievementSerializer(serializers.ModelSerializer):
    achievements = serializers.SerializerMethodField()
    achievements_count = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = ['achievements', 'achievements_count']

    def get_achievements(self, obj):
        if not obj.achievements:
            return []
        achievements = Achievement.objects.filter(id__in=obj.achievements)
        return AchievementSerializer(achievements, many=True).data

    def get_achievements_count(self, obj):
        return len(obj.achievements) if obj.achievements else 0


class AchievementListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Achievement
        fields = ['name', 'description', 'image', 'game_id']
        list_serializer_class = serializers.ListSerializer