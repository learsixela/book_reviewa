from django.urls import path
from . import views

urlpatterns = [
    path('', views.libros, name='libros'),
    path('agregar/', views.agregar, name='agregar'),
    path('insertar/',views.insertar, name='insertar'),
    path('recuperar/', views.recuperar, name='recuperar'),
    path('<int:libro_id>/', views.edit, name='edit'),
    path('add_review/', views.add_review, name='add_review'),
]