from rest_framework import serializers
from .models import User, Storage

class StorageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Storage
        fields = "__all__"

class UserSerializer(serializers.ModelSerializer):
    storages = StorageSerializer(many=True, read_only=True)  # связь с файлами
    class Meta:
        model = User
        fields = ["id_user", "username", "fullname", "email", "role", "storages", "password"]
        extra_kwargs = {
            "password": {"write_only": True},
        }

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password'],
            fullname=validated_data['fullname'],
            role=validated_data.get('role', 'user')  # Установка роли по умолчанию
        )
        return user