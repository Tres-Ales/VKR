import hashlib

from django.conf import settings
from django.contrib.auth.backends import ModelBackend

from users.models import User

from cwork1.my_hasher import STREEBOG


class PasswordlessAuthBackend(ModelBackend):
    """Log in to Django without providing a password.

    """
    def my_authenticate_CHAP(username=None, password_hash=None, string = None):
        try:
            user = User.objects.get(username=username)
            server_hash = hashlib.md5((user.password_name + string).encode('utf-8'))

            if server_hash.hexdigest() == password_hash:
                return user
            else:
                return None
        except User.DoesNotExist:
            return None

    def my_authenticate_skey(username=None, prev_password_hash = None):
        try:
            user = User.objects.get(username=username)
            #m = STREEBOG(digest_size = 64)
            #m.update(prev_password_hash)
            #client_hash = m.hexdigest()
            client_hash = hashlib.md5((prev_password_hash).encode('utf-8')).hexdigest()

            if client_hash == user.next_password_hash:

                user.next_password_hash = prev_password_hash

                user.number_of_iterations = user.number_of_iterations - 1
                user.save()
                return user
        except User.DoesNotExist:
            return None


    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None