from django.urls import path
from .views import (
    SignUpView,
    SignInView,
    ResetPasswordView,
    InviteMemberView,
    DeleteMemberView,
    UpdateMemberRoleView,
    RoleWiseUserCountView,
    OrganizationWiseMemberCountView,
    OrganizationRoleWiseUserCountView,
    FilteredOrganizationRoleWiseUserCountView
)

urlpatterns = [
    # Authentication-related routes
    path('signup/', SignUpView.as_view(), name='signup'),
    path('signin/', SignInView.as_view(), name='signin'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),

    # Member management routes
    path('invite-member/', InviteMemberView.as_view(), name='invite_member'),
    path('delete-member/<int:member_id>/', DeleteMemberView.as_view(), name='delete_member'),
    path('update-member-role/<int:member_id>/', UpdateMemberRoleView.as_view(), name='update_member_role'),

    # Stats routes
    path('stats/role-wise-users/', RoleWiseUserCountView.as_view(), name='role_wise_users'),
    path('stats/org-wise-members/', OrganizationWiseMemberCountView.as_view(), name='org_wise_members'),
    path('stats/org-role-wise-users/', OrganizationRoleWiseUserCountView.as_view(), name='org_role_wise_users'),
    
    # Filtered stats route
    path('stats/filtered-org-role-wise-users/', FilteredOrganizationRoleWiseUserCountView.as_view(), name='filtered_org_role_wise_users'),
]
