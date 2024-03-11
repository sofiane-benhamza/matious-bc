from datetime import datetime
from django.db import models
import os
from django.utils.html import escape
from django.db import connection


class users(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=32) 
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=64)
    recovery_answer = models.CharField(max_length=256) 
    class Meta:  
        db_table = "users"  

class aws_credentials(models.Model):
    user = models.ForeignKey(users, on_delete=models.CASCADE)
    unique_name = models.CharField(max_length=14) 
    date = models.DateField(default=datetime.now)
    aws_access_key_id = models.CharField(max_length=100) 
    aws_secret_access_key = models.CharField(max_length=100)
    class Meta:
        db_table = "aws_credentials"
        
class JWT(models.Model):
    user = models.ForeignKey(users, on_delete=models.CASCADE)
    token = models.TextField()
    expiration_time = models.DateTimeField()

    class Meta:
        db_table = "jwt"