from django.urls import path
from . import views

app_name = 'client'

urlpatterns = [
    path('', views.index, name='index'),
    path('api/execute/', views.execute_request, name='execute_request'),
    path('api/history/', views.history_api, name='history_api'),
]
