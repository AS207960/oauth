from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('pat_jwks.json', views.pat_jwks),
    path('pats/', views.personal_tokens, name='personal_tokens'),
    path('create_pat/', views.create_pat, name='create_pat'),
    path('verify_pat/', views.verify_pat),
    path('pat/<str:pat_id>/revoke/', views.revoke_pat, name='revoke_pat'),
    path('create_client/', views.create_client, name='create_client'),
    path('client/<uuid:client_id>/', views.view_client, name='view_client'),
    path('client/<uuid:client_id>/edit/', views.edit_client, name='edit_client'),
]
