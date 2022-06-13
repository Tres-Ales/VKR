import random
from random import randint

from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, UsernameField
#from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

from django.contrib.auth import get_user_model, authenticate
from django.utils.text import capfirst

from .admin import User_interests
from .models import QA, ManyQuestions, User_interest

User = get_user_model()

# FORMS
UserModel = get_user_model()
class KnowForm(forms.Form):

    def __init__(self, *args, **kwargs):
        str = kwargs.pop('str')
        seed = kwargs.pop('seed')
        super(KnowForm, self).__init__(*args, **kwargs)
        _user = User.objects.get(username=str)

        _count = ManyQuestions.objects.count()
        if (_count == 0):
            _allright = 3
        else:
            _ogr = ManyQuestions.objects.values_list('questions_all', flat=True)[_count - 1]
            _allright = _ogr

        _lst = list(User_interest.objects.filter(username=_user).values_list('interest', flat=True))


        random.Random(seed).shuffle(_lst)
        # _lstr = random.sample(_lst, _allright)
        _lst1 = []
        _lst2 = []
        for l in _lst:
            _lst2+=list(QA.objects.filter(id_qa=l).values_list('interest', flat=True))
        for l1 in _lst2:
            _lst1+=list(QA.objects.filter(interest=l1).values_list('contentqa', flat=True))

        for i in range(1, _allright+1):
            self.fields['content_{}: '.format(i)+_lst1[i-1]] = forms.CharField(max_length=150, required=False)



    class Meta:
        model = QA
        fields = ['content']

class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=30, required=False, help_text='Optional.')
    last_name = forms.CharField(max_length=30, required=False, help_text='Optional.')
    email = forms.EmailField(max_length=254, help_text='Required. Inform a valid email address.')

    #your_password = forms.CharField(widget=forms.PasswordInput(), validators=[min_length])


    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')

    #def save(self, request):
     #   user = super(SignUpForm, self).save(request)
     #   user.password_name = self.cleaned_data['password1']
      #  user.save()
       # return user
from django.utils.translation import gettext, gettext_lazy as _

class KnowledgeForm(forms.ModelForm):
    # def __init__(self, *args, **kwargs):
    #     super(KnowledgeForm, self).__init__(*args, **kwargs)
    #     instance = getattr(self, 'instance', None)
    #     if instance and instance.pk:
    #         self.fields['your_username'].widget.attrs['readonly'] = True

    _qs = QA.objects.values_list('interest',flat = True)
    _set = set(_qs)
    _set1 = list(_set)
    count = len(_set1)
    _MC = [(_set1[0], _set1[0])]
    for i in range (1,count,1):
        _MC.insert(0,(_set1[i],_set1[i]))

    _MC1 = tuple(_MC)
    #print(_set)
    Username = forms.CharField(max_length=254, widget=forms.TextInput(attrs={'readonly': 'readonly'}))

    field = forms.MultipleChoiceField(
        widget = forms.CheckboxSelectMultiple,
        # choices = _MC1
    )

    class Meta:
        model = User_interest
        fields = []

class NewAuthenticationForm(AuthenticationForm):
    urls = forms.CharField(max_length=100000, widget=forms.HiddenInput())


class SKeyIDForm(forms.Form):
    username = forms.CharField(max_length=254)

class SKeyForm(forms.Form):
    password = forms.CharField(label=_("Password"), widget=forms.PasswordInput)
    id_for_password = forms.CharField(max_length=254, widget=forms.HiddenInput())
    number_of_iterations = forms.IntegerField(widget=forms.HiddenInput())



class SetPasswordForm(forms.Form):
     new_password1 = forms.CharField(widget=forms.PasswordInput)
     new_password2 = forms.CharField(widget=forms.PasswordInput)

     error_messages = {
        'password_mismatch': ("The two password fields didn't match."),
        }


     class Meta:
         model = User
         fields = ('password',)
     def __init__(self,*args, **kwargs):
        super(SetPasswordForm, self).__init__(*args, **kwargs)

        def clean(self):
            cleaned_data = super(SetPasswordForm, self).clean()

            return cleaned_data