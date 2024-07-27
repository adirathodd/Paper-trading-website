from django.contrib import admin
from .models import User, Transaction
# Register your models here.
admin.site.register(User)
admin.site.register(Transaction)