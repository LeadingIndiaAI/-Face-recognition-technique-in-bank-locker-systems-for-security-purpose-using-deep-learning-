from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.forms import ModelForm
from django.core.validators import validate_email
from django import forms
from django.utils import timezone
from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model


class Myuser(AbstractUser):
    updated_on = models.DateTimeField(null=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.DO_NOTHING,null=True, db_constraint=False, related_name='created_user',
                                   related_query_name='created_user')
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.DO_NOTHING,null=True , db_constraint=False, related_name='updated_user',
                                   related_query_name='updated_user')
    password_reset_token=models.CharField(max_length=500, null=True)
    class Meta:
        db_table = 'auth_user'


class LoginLogs(models.Model):
    email = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    otp = models.CharField(max_length=6)
    otp_verified = models.PositiveSmallIntegerField(default=0)
    user_id = models.ForeignKey(settings.AUTH_USER_MODEL, db_constraint=False,on_delete=models.DO_NOTHING,null=True)
    logintry_time = models.DateTimeField(null=True,blank=True)
    login_time = models.DateTimeField(null=True,blank=True)
    logout_time = models.DateTimeField(null=True,blank=True)
    ip_address = models.CharField(max_length=20,null=True)
    agent = models.CharField(max_length=200,null=True)

    class Meta:
        get_latest_by = 'email'

class UserData(models.Model):
    lockerno = models.IntegerField(default=0)
    username = models.CharField(max_length=100)
    foldername = models.CharField(max_length=100)
