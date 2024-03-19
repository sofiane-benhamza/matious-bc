from django.db import models
from users.models import users

class tokenAuth(models.Model):
    user = models.ForeignKey(users, on_delete=models.CASCADE)
    token = models.TextField()
    expiration_time = models.DateTimeField()

    class Meta:
        db_table = "tokenAuth"
