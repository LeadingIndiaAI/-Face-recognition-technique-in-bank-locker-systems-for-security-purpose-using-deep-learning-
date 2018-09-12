from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.contrib.auth.backends import ModelBackend

class EmailBackend(ModelBackend):
    # Create an authentication method
    # This is called by the standard Django login procedure
    def authenticate(self, username=None, password=None):
        User = get_user_model()
        try:
            user = User.objects.get(email=username)
            if check_password(password, user.password):
                return user
            else:
                return None
        except User.DoesNotExist:
            print("Does not exist")
            return None
    # Required for your backend to work properly - unchanged in most scenarios
    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None