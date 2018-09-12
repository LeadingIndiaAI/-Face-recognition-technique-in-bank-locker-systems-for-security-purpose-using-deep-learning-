from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.core.validators import validate_email
from django.forms import ModelForm
from django import forms
from django.db import models
from django.utils import timezone
import datetime
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from .models import Myuser, LoginLogs, UserData
import re
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model

def lower_error(password):
    return re.search(r"[a-z]", password)

def symbol_error(password):
    return re.search(r"[!@$&]", password)

def upcase_error(password):
    return re.search(r"[A-Z]", password)

def digit_error(password):
    return re.search(r"\d", password)

class UserDataForm(ModelForm):
    class Meta:
        model=UserData
        fields = ['lockerno','username']

class UserLoginA(ModelForm):
    class Meta:
        model=UserData
        fields = ['lockerno']

class MyuserForm(ModelForm):
    password = forms.CharField(max_length=100, widget=forms.PasswordInput())
    class Meta:
        model=get_user_model()
        fields = ['username','email','password']

    def __init__(self, *args, **kwargs):
        self.logged_admin = kwargs.pop('logged_admin')  # accessing the request.user in current request coming from view file
        super(MyuserForm, self).__init__(*args, **kwargs)

    def save(self, commit=True):
        instance = super(MyuserForm, self).save(commit=False)
        if instance.pk is None:
            instance.date_joined = datetime.datetime.now()
            instance.updated_on = datetime.datetime.now()
            instance.created_by_id = self.logged_admin
            instance.updated_by_id = self.logged_admin
            instance.password = make_password(self.cleaned_data['password'])
        else:
            instance.updated_on = datetime.datetime.now()
            instance.updated_by_id = self.logged_admin
            instance.password = make_password(self.cleaned_data['password'])

        if commit:
            instance.save()
        return instance

    def clean_email(self):
        email = self.cleaned_data['email']
        try:
            validate_email(email)
        except:
            raise forms.ValidationError("This is not a valid email")
        return email

    def clean_password(self):
        password = self.cleaned_data['password']
        if len(password)<8 or lower_error(password) is None or upcase_error(password) is None or digit_error(password) is None or symbol_error(password) is None :
            raise forms.ValidationError(
                     "{} is invalid, must have minimum 8 characters, 1 uppercase, 1 lowercase, 1 special character and 1 digit should be present".format(password))
        else:
            return password


    # def clean_password(self):
    #     password = self.cleaned_data['password']
    #     print(password)
    #     try:
    #         re.search(r'[A-Za-z0-9@#$%^&+=]{8,20}', password)
    #         raise forms.ValidationError(
    #             "{} is invalid, must have 8 characters in which 1 uppercase, 1 lowercase, 1 special character and 1 digit should be present".format(password))
    #     except:
    #         return password

class LoginLogsForm(ModelForm):
    password = forms.CharField(max_length=100, widget=forms.PasswordInput())
    class Meta:
        model=LoginLogs
        fields = ['email','password']


class OtpVeriForm(ModelForm):
    otp = models.CharField(max_length=6)
    class Meta:
        model=LoginLogs
        fields = ['otp']
    def clean_otp(self):
        otp = self.cleaned_data['otp']
        if len(otp) != 6:
            raise forms.ValidationError(" OTP must be of lenght 6.")
        else:
            return otp



class PasswordResetForm(ModelForm):
    class Meta:
        model=get_user_model()
        fields = ['email']


class PasswordResetWithTokenForm(ModelForm):
    new_password = forms.CharField(max_length=100, widget=forms.PasswordInput())
    retype_newpassword = forms.CharField(max_length=100, widget=forms.PasswordInput())
    class Meta:
        model=get_user_model()
        fields = ['new_password','retype_newpassword']

    def clean_new_password(self):
        new_password = self.cleaned_data['new_password']
        if len(new_password)<8 or lower_error(new_password) is None or upcase_error(new_password) is None or digit_error(new_password) is None or symbol_error(new_password) is None :
            raise forms.ValidationError(
                     "{} is invalid, must have minimum 8 characters, 1 uppercase, 1 lowercase, 1 special character and 1 digit should be present".format(new_password))
        else:
            return new_password


class PasswordChangeForm(ModelForm):
    old_password = forms.CharField(max_length=100, widget=forms.PasswordInput())
    new_password = forms.CharField(max_length=100, widget=forms.PasswordInput())
    retype_newpassword = forms.CharField(max_length=100, widget=forms.PasswordInput())
    class Meta:
        model=get_user_model()
        fields = ['old_password','new_password','retype_newpassword']

    def clean_new_password(self):
        new_password = self.cleaned_data['new_password']
        if len(new_password)<8 or lower_error(new_password) is None or upcase_error(new_password) is None or digit_error(new_password) is None or symbol_error(new_password) is None:
            raise forms.ValidationError(
                "{} is invalid, must have minimum 8 characters, 1 uppercase, 1 lowercase, 1 special character and 1 digit should be present".format(new_password))
        else:
            return new_password
