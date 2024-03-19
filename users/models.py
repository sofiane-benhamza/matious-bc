from datetime import datetime
from django.db import models
import os
from django.utils.html import escape
from django.db import connection


class users(models.Model):
    id = models.AutoField(primary_key=True)
    first_name = models.CharField(max_length=32) 
    last_name = models.CharField(max_length=32) 
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=64)
    role = models.CharField(max_length=32) 
    class Meta:  
        db_table = "users"  
        
'''class JWT(models.Model):
    user = models.ForeignKey(users, on_delete=models.CASCADE)
    token = models.TextField()
    expiration_time = models.DateTimeField()

    class Meta:
        db_table = "jwt"'''