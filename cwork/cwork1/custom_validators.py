# VALIDATION FOR PASSWORD
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _, ngettext

#from users.views import params
from users.models import Password_params

params_all = Password_params.objects.all()
num = Password_params.objects.count()


class MinLengthValidator(object):
    def __init__(self, min_length=8):  # put default min_length here
        if (num!=0 and params_all[num-1].length > 8):
            self.min_length = params_all[num-1].length
        else: self.min_length = min_length

    def validate(self, password, user=None):
        #print(self.min_length)
        if len(password) < self.min_length:
            raise ValidationError(_('Password must contain at least %(min_length)d digit.') % {'min_length': self.min_length})#(
                #ngettext(

                 #   "This password is too short. It must contain at least %(min_length)d character.",

                 #   "This password is too short. It must contain at least %(min_length)d characters.",
                 #   self.min_length
                #),

                #code='password_too_short',
                #params={'min_length': self.min_length},
            #)

    def get_help_text(self):
        return ngettext(

            "Your password must contain at least %(min_length)d character.",
            "Your password must contain at least %(min_length)d characters.",
            self.min_length
        ) % {'min_length': self.min_length}


# SPECIAL SYMBOLS VALIDATION
class SpecialSymbolsValidator(object):
    #global params_all, num

    def __init__(self, min_length=0):  # put default min_length here
        if (num!=0 and params_all[num-1].number_of_special_symbols > 0):
            self.min_length = params_all[num-1].number_of_special_symbols

        else: self.min_length = min_length

    def validate(self, password, user=None):
        stroka = str(password)
        k = 0
        symbols = ['+', '-', '?', '!', '@', '&', '$', '#', '|', '_', '~', ']', '[', '{', '}', '<', '>', ':', ';', '%',
                   '*']
        for el in stroka:
            if (el in symbols):
                k+=1
        if k < self.min_length:
            raise ValidationError(
                ngettext(

                    "This password must contain at least %(min_length)d special character.",

                    "This password must contain at least %(min_length)d special characters.",
                    self.min_length
                ),
                code='too_few_special_symbols',
                params={'min_length': self.min_length},
            )

    def get_help_text(self):
        return ngettext(

            "Your password must contain at least %(min_length)d special character.(like +/-/|/[/{/?/!)",
            "Your password must contain at least %(min_length)d special characters.(like +/-/|/[/{/?/!)",
            self.min_length
        ) % {'min_length': self.min_length}


# UPPERCASE VALIDATION
class UpperCaseValidator(object):
    # global params_all, num

    def __init__(self, flag = 0):  # put default min_length here

        if (num != 0 and params_all[num - 1].uppercase_symbols == 'yes' or \
                num != 0 and params_all[num - 1].uppercase_symbols == 'Yes' ):
            self.flag = 1
        else:
            self.flag = 0


    def validate(self, password, user=None):
        stroka = str(password)
        upels = False

        for el in stroka:
            if el.isupper():
                upels=True
        if self.flag and not upels:
            raise ValidationError(
                ngettext(
                    "This password must contain at least %(flag)d uppercase character.",
                    "This password must contain at least %(flag)d uppercase characters.",
                    self.flag
                ),
                code='no_uppercase_symbols',
                params={'flag': self.flag},
            )

    def get_help_text(self):
        return ngettext(
            "Your password must contain at least %(flag)d uppercase character.",
            "Your password must contain at least %(flag)d uppercase characters.",
            self.flag
        ) % {'flag': self.flag}