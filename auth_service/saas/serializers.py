from rest_framework import serializers
from .models import User, Organization, Member, Role

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)  # Ensure password is not read in responses

    class Meta:
        model = User
        fields = ['email', 'password', 'profile', 'status', 'created_at', 'updated_at']

    def create(self, validated_data):
        user = User(
            email=validated_data['email'],
            profile=validated_data.get('profile', {}),
            status=validated_data.get('status', 0)
        )
        user.set_password(validated_data['password'])  # Hash the password
        user.save()
        return user

class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ['name', 'status', 'personal', 'settings', 'created_at', 'updated_at']

class MemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Member
        fields = ['org_id', 'user_id', 'role_id', 'status', 'settings', 'created_at', 'updated_at']

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['name', 'description', 'org_id']
