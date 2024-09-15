from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from .models import Organization, Member, Role
from .serializers import UserSerializer, OrganizationSerializer, MemberSerializer, RoleSerializer
from rest_framework.permissions import AllowAny
from django.core.mail import send_mail
from django.core.exceptions import ValidationError
import datetime
# from sendgrid import SendGridAPIClient
# from sendgrid.helpers.mail import Mail 
from django.db import models
import os

class SignUpView(APIView):
    permission_classes = [AllowAny] 

    def post(self, request):
        user_data = request.data.get('user')
        org_data = request.data.get('organization')

        user_serializer = UserSerializer(data=user_data)
        if user_serializer.is_valid():
            user = user_serializer.save()

            org_serializer = OrganizationSerializer(data=org_data)
            if org_serializer.is_valid():
                org = org_serializer.save()

                owner_role = Role.objects.create(name="Owner", org_id=org)
                Member.objects.create(user_id=user, org_id=org, role_id=owner_role)
                
                return Response({"message": "User and organization created successfully"}, status=status.HTTP_201_CREATED)
        
        return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SignInView(APIView):
    permission_classes = [AllowAny] 

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        try:
            user = User.objects.get(email=email)
            if user.check_password(password):
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                })
            return Response({"message": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        new_password = request.data.get('new_password')
        print(email,new_password)
        try:
            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()

            return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
        
        except User.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class InviteMemberView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        org_id = request.data.get('org_id')
        email = request.data.get('email')
        role_id = request.data.get('role_id')

        try:
            org = Organization.objects.get(id=org_id)
            role = Role.objects.get(id=role_id)

            user, created = User.objects.get_or_create(email=email)
            if created:
                self.send_invite_email(email, org.name)  # Use the organization name for clarity

            Member.objects.create(user=user, org=org, role=role)
            return Response({"message": "Member invited successfully"}, status=status.HTTP_201_CREATED)
        except Organization.DoesNotExist:
            return Response({"message": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)
        except Role.DoesNotExist:
            return Response({"message": "Role not found"}, status=status.HTTP_404_NOT_FOUND)

    def send_invite_email(self, email, org_name):
        subject = f"You're invited to join {org_name}"
        message = f"Hi,\n\nYou've been invited to join {org_name}. Please click the link below to accept the invitation.\n\n[Invite Link]\n\nThanks!"
        from_email = 'roshanshankar025@gmail.com'
        
        send_mail(subject, message, from_email, [email])

class DeleteMemberView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, member_id):
        try:
            member = Member.objects.get(id=member_id)
            member.delete()
            return Response({"message": "Member deleted successfully"}, status=status.HTTP_200_OK)
        except Member.DoesNotExist:
            return Response({"message": "Member not found"}, status=status.HTTP_404_NOT_FOUND)
        
    
class UpdateMemberRoleView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, member_id):
        role_id = request.data.get('role_id')
        try:
            member = Member.objects.get(id=member_id)
            role = Role.objects.get(id=role_id)
            member.role_id = role
            member.save()
            return Response({"message": "Member role updated successfully"}, status=status.HTTP_200_OK)
        except Member.DoesNotExist:
            return Response({"message": "Member not found"}, status=status.HTTP_404_NOT_FOUND)
        except Role.DoesNotExist:
            return Response({"message": "Role not found"}, status=status.HTTP_404_NOT_FOUND)

class RoleWiseUserCountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        role_wise_count = Member.objects.values('role_id__name').annotate(user_count=models.Count('user_id'))
        return Response(role_wise_count)

class OrganizationWiseMemberCountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        org_wise_count = Member.objects.values('org_id__name').annotate(member_count=models.Count('user_id'))
        return Response(org_wise_count)

class OrganizationRoleWiseUserCountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        org_role_wise_count = Member.objects.values('org_id__name', 'role_id__name').annotate(user_count=models.Count('user_id'))
        return Response(org_role_wise_count)

class FilteredOrganizationRoleWiseUserCountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from_time = request.query_params.get('from_time')
        to_time = request.query_params.get('to_time')
        status = request.query_params.get('status')

        members = Member.objects.all()

        if from_time:
            try:
                from_time = datetime.strptime(from_time, '%Y-%m-%d')
                members = members.filter(created_at__gte=from_time)
            except ValueError:
                raise ValidationError("Invalid from_time format. Use YYYY-MM-DD.")

        if to_time:
            try:
                to_time = datetime.strptime(to_time, '%Y-%m-%d')
                members = members.filter(created_at__lte=to_time)
            except ValueError:
                raise ValidationError("Invalid to_time format. Use YYYY-MM-DD.")

        if status:
            members = members.filter(status=status)

        org_role_wise_count = members.values('org_id__name', 'role_id__name').annotate(user_count=models.Count('user_id'))
        return Response(org_role_wise_count)

def send_invite_email(email, org_id):
    message = Mail( # type: ignore
        from_email='your-email@example.com',
        to_emails=email,
        subject='You have been invited to join an organization',
        html_content=f'<strong>Click the link to accept the invite and join the organization: http://your-domain.com/invite/{org_id}/</strong>'
    )
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY')) # type: ignore
        response = sg.send(message)
        return response
    except Exception as e:
        print(f"Error sending email: {e}")
