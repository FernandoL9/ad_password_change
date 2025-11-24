from django.urls import path
from .views import (
    UserExistsView, UserInfoView, UserPhoneView, ListUsersView, PasswordResetView,
    MFAGenerateCodeView, MFAVerifyCodeView, MFAGetCurrentCodeView
)


urlpatterns = [
    path('user/exists', UserExistsView.as_view(), name='user-exists'),
    path('user/info', UserInfoView.as_view(), name='user-info'),
    path('user/phone', UserPhoneView.as_view(), name='user-phone'),
    path('users/list', ListUsersView.as_view(), name='users-list'),
    path('password/reset', PasswordResetView.as_view(), name='password-reset'),
    # MFA Routes
    path('mfa/generate', MFAGenerateCodeView.as_view(), name='mfa-generate'),
    path('mfa/verify', MFAVerifyCodeView.as_view(), name='mfa-verify'),
    path('mfa/current', MFAGetCurrentCodeView.as_view(), name='mfa-current'),
]


