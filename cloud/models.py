from django.db import models
from datetime import datetime
from django.db import models
import os
from django.utils.html import escape
from django.db import connection
from users.models import users


class aws_credentials(models.Model):
    user = models.ForeignKey(users, on_delete=models.CASCADE)
    unique_name = models.CharField(max_length=14) 
    date = models.DateField(default=datetime.now)
    aws_access_key_id = models.CharField(max_length=100) 
    aws_secret_access_key = models.CharField(max_length=100)
    class Meta:
        db_table = "aws_credentials"
