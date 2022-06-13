from django.db import models
from django.contrib.auth.models import PermissionsMixin, UserManager
from django.apps import apps
from django.contrib import auth
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.hashers import make_password
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.db import models
from django.db.models.manager import EmptyManager
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .managers import UserManager

class Password_params(models.Model):
    STATUS_CHOICES = (
        ('Yes', 'yes'),
        ('No', 'no'),
    )
    namepass = models.CharField(max_length=250, default='pass1')
    length = models.IntegerField(default = 8)
    uppercase_symbols = models.CharField(max_length=250, choices=STATUS_CHOICES, default='No')
    number_of_special_symbols = models.IntegerField(default = 0)
    number_of_digits = models.IntegerField(default = 3)

    def __str__(self):
        return self.namepass


class User(AbstractBaseUser, PermissionsMixin):
    #STATUS_CHOICES =
    #__tablename__ = 'user'
    username_validator = UnicodeUsernameValidator()

    username = models.CharField(_('username'),
        max_length=150,
        unique=True,
        help_text=_('Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        validators=[username_validator],
        error_messages={
            'unique': _("A user with that username already exists."),
        },)
    first_name = models.CharField(_('first name'), max_length=150, blank=True)
    last_name = models.CharField(_('last name'), max_length=150, blank=True)
    password_name = models.CharField(_('password name'), max_length=150, blank=True)
    email = models.EmailField(_('email address'), blank=True)

    #fields = models.ForeignKey('QA', db_column='fieldKnow', on_delete=models.CASCADE, null = True)

    no_secret_number = models.IntegerField(_('no secret number'), blank=True, null=True)
    number_of_iterations = models.IntegerField(_('number_of_iterations'), blank=True, null=True)
    next_password_hash = models.CharField(_('next_password_hash'), max_length=350, blank=True, null=True)

    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = UserManager()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        #abstract = True

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def get_password_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        return self.password_name

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)



class Interests(models.Model):
    id = models.IntegerField(unique=True, primary_key=True)
    content = models.CharField(max_length=40, default='content')

    def __str__(self):
        return self.content

class User_interest(models.Model):
    id_ui = models.IntegerField(unique=True, primary_key=True)
    username = models.ForeignKey('User', db_column='username', on_delete=models.CASCADE, null = True)
    interest = models.ForeignKey('Interests', db_column='id', on_delete=models.CASCADE, null = True, blank=True)


class QA(models.Model):
    id_qa = models.IntegerField(unique=True, primary_key=True)
    interest = models.ForeignKey('interests', db_column='content', on_delete=models.CASCADE, null = True, blank=True)
    contentqa = models.CharField(max_length=500, default='question')
    answer = models.CharField(max_length=50, default='ans')

    def __str__(self):
        return self.content


class ManyQuestions(models.Model):
    name = models.CharField(max_length=250, default='pass1')
    questions_all = models.IntegerField(default = 3)
    questions_right = models.IntegerField(default = 2)

    def __str__(self):
        return self.name


class Keywords(models.Model):
    id_k = models.IntegerField(unique=True, primary_key=True)
    interest = models.ForeignKey('Interests', db_column='content', on_delete=models.CASCADE, null = True, blank=True)
    contentkey = models.CharField(max_length=50, default='content')

    def __str__(self):
        return self.contentkey
