
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

class Organization(models.Model):
    name = models.CharField(max_length=255, null=False)
    status = models.IntegerField(default=0, null=False)
    personal = models.BooleanField(default=False, null=True)
    settings = models.JSONField(default=dict, null=True)
    created_at = models.BigIntegerField(null=True)
    updated_at = models.BigIntegerField(null=True)

    def __str__(self):
        return self.name

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    email = models.EmailField(unique=True, null=False)
    password = models.CharField(max_length=255, null=False)
    profile = models.JSONField(default=dict)
    status = models.IntegerField(default=0, null=False)
    settings = models.JSONField(default=dict, null=True)
    created_at = models.BigIntegerField(null=True)
    updated_at = models.BigIntegerField(null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

class Role(models.Model):
    name = models.CharField(max_length=255, null=False)
    description = models.TextField(null=True)
    org_id = models.ForeignKey(Organization, on_delete=models.CASCADE)

class Member(models.Model):
    org_id = models.ForeignKey(Organization, on_delete=models.CASCADE)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    role_id = models.ForeignKey(Role, on_delete=models.CASCADE)
    status = models.IntegerField(default=0, null=False)
    settings = models.JSONField(default=dict, null=True)
    created_at = models.BigIntegerField(null=True)
    updated_at = models.BigIntegerField(null=True)
