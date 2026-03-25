from django.urls import path, include

from .views import health

urlpatterns = [
    path('health/', health, name='health'),
    path('api/', include('accounts.urls')),
]


