from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('create_client/', views.create_client, name='create_client'),
    path('client/<uuid:client_id>/', views.view_client, name='view_client'),
    path('client/<uuid:client_id>/edit/', views.edit_client, name='edit_client'),
]
