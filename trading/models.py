from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    balance = models.DecimalField(max_digits=65, decimal_places=2, default = 10000)
    emailVerified = models.BooleanField(default= False)

class Transaction(models.Model):
    user = models.ForeignKey(User, on_delete = models.CASCADE, related_name = "user")
    stock = models.CharField(max_length=10)
    shares = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    currentValue = models.DecimalField(max_digits=65, decimal_places=2, null = True, blank = True)