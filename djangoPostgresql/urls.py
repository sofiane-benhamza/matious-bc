"""djangoPostgresql URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from djanpost import views

urlpatterns = [
    path('', views.main),
    path('users/add/', views.add_user_view),
    path('users/update/', views.update_user_view),
    path('users/show/', views.show_users_view),
    path('users/verify/', views.verify_user_view),
    path('users/get/', views.get_user_info_view),
    path('credentials/add/', views.add_credentials_view),
    path('users/logout/', views.logout_view),
]
