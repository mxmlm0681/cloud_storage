import os

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('Поле электронной почты должно быть заполнено')
        if not username:
            raise ValueError('Поле пользователя должно быть заполнено')

        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, username, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    id_user = models.AutoField(primary_key=True)
    email = models.EmailField(max_length=128, unique=True, null=False)
    username = models.CharField(max_length=128, unique=True, null=False)
    fullname = models.CharField(max_length=128, null=False)
    role = models.CharField(max_length=128, default="user")

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    class Meta:
        db_table = "users"

    def __str__(self):
        return self.username


class Storage(models.Model):
    id_file = models.AutoField(primary_key=True)
    id_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="storages", db_column="user_id")
    original_name = models.CharField(max_length=128, null=False)
    new_name = models.CharField(max_length=128, null=True, blank=True)
    comment = models.CharField(max_length=128, null=False)
    size = models.BigIntegerField()
    upload_date = models.DateTimeField(auto_now_add=True, db_column="upload_date")
    last_download_date = models.DateTimeField(null=True, auto_now=False, blank=True, db_column="last_download_date")
    file = models.FileField(upload_to='uploads/')
    token = models.CharField(max_length=32, null=True, blank=True)
    token_expiration = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "storage"

    def __str__(self):
        return self.original_name

    def delete(self, *args, **kwargs):
        # Удаляем файл из файловой системы
        if self.file:
            if os.path.isfile(self.file.path):
                os.remove(self.file.path)
        super(Storage, self).delete(*args, **kwargs)
