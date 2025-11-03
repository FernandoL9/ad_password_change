from django.urls import path
from .views import UserExistsView, PasswordResetView


urlpatterns = [
    path('user/exists', UserExistsView.as_view(), name='user-exists'),
    path('password/reset', PasswordResetView.as_view(), name='password-reset'),
]


