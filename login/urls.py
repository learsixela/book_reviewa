from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.login, name='login'),
    path('registrar', views.registrar, name='registrar'),
    path('login', views.inicio, name='inicio'),
    path('registro', views.registro, name='registro'),
    path('logout', views.logout, name='logout'),
    path('users/<int:user_id>', views.view_user, name='view_user'),
]