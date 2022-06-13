import datetime
import hashlib
import re
import uuid
from random import randint, seed

from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm, AuthenticationForm, PasswordResetForm
from django.contrib.auth.tokens import PasswordResetTokenGenerator, default_token_generator
from django.contrib.auth.views import INTERNAL_RESET_SESSION_TOKEN, PasswordContextMixin, SuccessURLAllowedHostsMixin
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError, ImproperlyConfigured
from django.db.models import Q

from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import get_user_model, update_session_auth_hash, login, REDIRECT_FIELD_NAME
from django.template.context_processors import csrf
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.urls import reverse_lazy, reverse
from django.utils.crypto import constant_time_compare
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_text
from django.utils.html import format_html
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode, url_has_allowed_host_and_scheme, is_safe_url

import sys

from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView

from cwork1 import settings

from cwork1.my_hasher import STREEBOG

from cwork1.auth_backend import PasswordlessAuthBackend

from . import CheckToLogin

sys.path.append('/course_work/cwork/cwork1/settings')
from cwork1.settings import EMAIL_HOST_USER


# VIEW FOR HOME PAGE
def dashboard(request):
    return render(request, 'users/dashboard.html', {'section': 'dashboard'})


# SIGN UP WITH CONFIRMATION BY EMAIL
from django.shortcuts import render, resolve_url, redirect
from .forms import SignUpForm, SKeyForm, SKeyIDForm, KnowledgeForm, KnowForm, \
    NewAuthenticationForm
from django.core.mail import send_mail, EmailMessage, EmailMultiAlternatives, BadHeaderError

from django.contrib.auth import get_user_model

user = get_user_model()
from django.utils.translation import gettext_lazy as _

account_activation_token = PasswordResetTokenGenerator()

INTERNAL_RESET_SESSION_TOKEN = '_password_reset_token'

from .models import User, QA, ManyQuestions, User_interest, Interests

""" СДЕЛАТЬ КНОПКУ ЧУЖОЙ КОМПЬЮТЕР? ОНА БУДЕТ ПЕРЕВОДИТ НА ФОРМУ С ВОПРОСАМИ И ПОЛЯМИ ДЛЯ ОТВЕТОВ 
И УЖЕ ПОСЛЕЕЕ ЛОГИНИТЬСЯ!"""


class TwoLogin:
    username = ""
    user = None
    redirect_to = ""
    seed = 0


def login(request, template_name='users/registrate/login.html',
          redirect_field_name=REDIRECT_FIELD_NAME,
          authentication_form=AuthenticationForm,
          current_app=None, extra_context=None, helpmod=TwoLogin):
    """
    Displays the login form and handles the login action.
    """
    redirect_to = request.POST.get(redirect_field_name,
                                   request.GET.get(redirect_field_name, ''))

    if request.method == "POST":
        form = authentication_form(request, data=request.POST)
        if form.is_valid():

            # Ensure the user-originating redirection url is safe.
            if not is_safe_url(url=redirect_to, allowed_hosts=request.get_host()):
                redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)
            if request.POST.get('toKnow'): # Выбран чужой компьютер
                usn = helpmod.username = form.get_user().username
                helpmod.user = form.get_user()
                helpmod.redirect_to = redirect_to
                helpmod.seed = randint(2, 6)

                user_id = list(User.objects.filter(username=usn).values_list('id', flat=True))[0]
                # return HttpResponseRedirect('Know/')
                # print(form.get_user().username)
                # form = KnowForm(form.get_user().username)

                db_interests1 = list(User_interest.objects.filter(username=user_id).values_list('interest', flat=True))

                db_interests = []
                for interest in db_interests1:
                    db_interests.append(list(Interests.objects.filter(id=interest).values_list('content', flat=True))[0])

                k = 0
                for idb in db_interests:
                    print(idb)
                    if request.POST.get(idb):
                        k+=1
                if (k==len(db_interests)):
                    return redirect('Know/')
                else:
                    messages.info(request, 'Неправильно выбраны интересы')
            else:
                # Okay, security check complete. second factor.
                url_array = request.POST.get("urls_a").split(',')

                if not CheckToLogin.checkToAuth(url_array, form.get_user().username):
                    messages.info(request, 'Произошла ошибка аутентификации пользователя. Попробуйте снова')

                else:
                    auth_login(request, form.get_user())
                    return HttpResponseRedirect(redirect_to)
    else:
        form = authentication_form(request)

    current_site = get_current_site(request)

    context = {
        'form': form,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
        'db_interests' : list(Interests.objects.values_list('content', flat=True)),
    }
    if extra_context is not None:
        context.update(extra_context)

    if current_app is not None:
        request.current_app = current_app

    return TemplateResponse(request, template_name, context)


def Know(request, template_name='users/registrate/loginKnow.html',
         redirect_field_name=REDIRECT_FIELD_NAME,
         authentication_form=KnowForm,
         current_app=None, extra_context=None, helpmod=TwoLogin):
    """
    Displays the login form and handles the login action.
    """
    redirect_to = helpmod.redirect_to

    if request.method == "POST":
        form = authentication_form(request.POST, str=helpmod.username, seed=helpmod.seed)
        if form.is_valid():

            # Ensure the user-originating redirection url is safe.
            if not is_safe_url(url=redirect_to, allowed_hosts=request.get_host()):
                redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)
            else:
                _lst = form.cleaned_data
                print(_lst)
                _keys1 = list(_lst.keys())
                _values = list(_lst.values())
                _keys = []
                for k in _keys1:
                    _keys.append(k[k.find(' ') + 1:])
                schetchik = 0
                for i in range(len(_keys)):
                    # print(list(QA.objects.filter(contentqa=_keys[i]).values_list('answer', flat=True))[0])
                    if list(QA.objects.filter(contentqa=_keys[i]).values_list('answer', flat=True))[0].lower() == \
                            _values[i].lower():
                        schetchik += 1

                _count = ManyQuestions.objects.count()
                if (_count == 0):
                    shetchik_right = 2
                else:
                    _ogr = ManyQuestions.objects.values_list('questions_right', flat=True)[_count - 1]
                    shetchik_right = _ogr

                if (schetchik >= shetchik_right):
                    # Okay, security check complete. Log the user in.
                    auth_login(request, helpmod.user)
                    return HttpResponseRedirect(redirect_to)
                else:
                    return HttpResponse('Вы не ответили на нужное количество вопросов правильно, попробуйте зарегистрироваться снова')
    else:
        form = authentication_form(str=helpmod.username, seed=helpmod.seed)

    current_site = get_current_site(request)

    context = {
        'form': form,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
    }
    if extra_context is not None:
        context.update(extra_context)

    if current_app is not None:
        request.current_app = current_app

    return TemplateResponse(request, template_name, context)


# NEW SIGNUP AFTER CHANGING USER MODEL
class REG:
    user = None


def signup(request, helpmod=REG):
    # print(users_all.password_name)
    # users_all = User.objects.all()
    # num = Password_params.objects.count()

    if request.method == "POST":
        form = SignUpForm(request.POST)
        print(form.errors)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            password_name = form.cleaned_data.get('password1')
            user = form.save()

            userdata = User.objects.all()
            for userinfo in userdata:
                if userinfo.username == user.username:
                    user_un = user.username
            update_data = User.objects.get(username=user_un)
            # DATA FOR CHAP
            update_data.password_name = password_name
            # DATA FOR SKEY
            update_data.number_of_iterations = 500
            # код инициализации
            seed = randint(0, 10000)
            update_data.no_secret_number = seed
            # m = STREEBOG(digest_size=64)
            # m.update(password_name+str(seed))
            # update_data.next_password_hash = m.count_iterations(501).hexdigest()

            string = password_name + str(seed)
            for i in range(501):
                string = hashlib.md5(string.encode('utf-8')).hexdigest()
            update_data.next_password_hash = string

            update_data.save()
            """ЗДЕСЬ ПЕРЕХОД НА ФОРМУ CHOICES"""
            # form = KnowledgeForm(initial = {'un' : user_un})
            # return render(request, 'users/sign_up/choices.html', {'form': form})
            current_site = get_current_site(request)
            mail_subject = 'Activate your account.'
            message = render_to_string('users/sign_up/signup_email.html', {
                'protocol': 'http',
                'user': helpmod.user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(helpmod.user.pk)),
                'token': account_activation_token.make_token(helpmod.user),
            })
            to_email = helpmod.user.email
            msg = EmailMessage(mail_subject, message, EMAIL_HOST_USER, [to_email])
            msg.content_subtype = "html"
            # send_mail(mail_subject, message, EMAIL_HOST_USER, [to_email])
            msg.send()

            url_array = request.POST.get("urls_a").split(',')
            CheckToLogin.setInterestsRegistration(url_array, user.username)

            form = AuthenticationForm(request)
            return render(request, 'users/registrate/login.html', {'form': form})
            # helpmod.user = user
            # form = KnowledgeForm()
            # return HttpResponseRedirect('choices/')
            # return HttpResponse('Please confirm your email address to complete the registration')
        else:
            return HttpResponse('Could not registrate you')

    else:
        form = SignUpForm()
        return render(request, 'users/sign_up/signup.html', {'form': form})


def choose(request, helpmod=REG):
    if request.method == 'POST':
        form = KnowledgeForm(request.POST)

        print(form.errors)
        if form.is_valid():

            _lst = request.POST.getlist('interest')
            if (len(_lst) < 0): return HttpResponse('Вернитесь и выберите как минимум 3 области знаний')
            # print(_lst)
            for item in _lst:
                _user = User.objects.get(username=form.cleaned_data['Username'])
                _qa = QA.objects.filter(interest=item)
                # update_data = User.objects.get(username=user_un)
                update_data = User_interest.objects.create(field=_qa[0], username=_user)
            # user = User.objects.filter(username = helpmod.user.username)
            current_site = get_current_site(request)
            mail_subject = 'Activate your account.'
            message = render_to_string('users/sign_up/signup_email.html', {
                'protocol': 'http',
                'user': helpmod.user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(helpmod.user.pk)),
                'token': account_activation_token.make_token(helpmod.user),
            })
            to_email = helpmod.user.email
            msg = EmailMessage(mail_subject, message, EMAIL_HOST_USER, [to_email])
            msg.content_subtype = "html"
            # send_mail(mail_subject, message, EMAIL_HOST_USER, [to_email])
            msg.send()
            # Update_data = update_data()

            # Update_data.save()
            # uf = User_Field.model(username = form.cleaned_data('un'), field = item.name)
            # uf.save(using=User_Field._db)
            #return render(request, 'users/sign_up/PleaseConfirm', {'form': form})
            #return redirect('users/')
            form = AuthenticationForm(request)
            return render(request, 'users/registrate/login.html', {'form': form})

    else:
        form = KnowledgeForm(initial={'Username': helpmod.user.username})
        return render(request, 'users/sign_up/choices.html', {'form': form})



""" ФОРМА CHOICES ПО ПРИМЕРУ ИЗ БРАУЗЕРА С QUERYSET, КОТОРАЯ РЕДИРЕКТИТ НА КОНФЕРМ! """


def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return render(request, 'users/sign_up/confirmed.html', {
            'section': 'activate'})  # HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')


# NEW PASSWORD CHANGE
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            password_name = form.cleaned_data.get('new_password1')
            userdata = User.objects.all()
            for userinfo in userdata:
                if userinfo.username == user.username:
                    user_un = user.username
            update_data = User.objects.get(username=user_un)
            update_data.password_name = password_name
            # DATA FOR SKEY

            # код инициализации
            update_data.number_of_iterations = 500
            # код инициализации
            seed = randint(0, 10000)
            update_data.no_secret_number = seed

            string = password_name + str(seed)
            for i in range(501):
                string = hashlib.md5(string.encode('utf-8')).hexdigest()
            update_data.next_password_hash = string

            update_data.save()
            return render(request, 'users/registrate/password_change_done.html')
        else:
            messages.error(request, ('Please correct the error below.'))
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'users/registrate/password_change_form.html', {
        'form': form
    })


# NEW PASSWORD RESET AFTER CHANGING USER MODEL
UserModel = get_user_model()


class PasswordResetConfirmView(PasswordContextMixin, FormView):
    form_class = SetPasswordForm
    post_reset_login = False
    post_reset_login_backend = None
    reset_url_token = 'set-password'
    success_url = reverse_lazy('password_reset_complete')
    template_name = 'registration/password_reset_confirm.html'
    title = _('Enter new password')
    token_generator = default_token_generator

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        if 'uidb64' not in kwargs or 'token' not in kwargs:
            raise ImproperlyConfigured(
                "The URL path must contain 'uidb64' and 'token' parameters."
            )

        self.validlink = False
        self.user = self.get_user(kwargs['uidb64'])

        if self.user is not None:
            token = kwargs['token']
            if token == self.reset_url_token:
                session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
                if self.token_generator.check_token(self.user, session_token):
                    # If the token is valid, display the password reset form.
                    self.validlink = True
                    return super().dispatch(*args, **kwargs)
            else:
                if self.token_generator.check_token(self.user, token):
                    # Store the token in the session and redirect to the
                    # password reset form at a URL without the token. That
                    # avoids the possibility of leaking the token in the
                    # HTTP Referer header.
                    self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
                    redirect_url = self.request.path.replace(token, self.reset_url_token)
                    return HttpResponseRedirect(redirect_url)

        # Display the "Password reset unsuccessful" page.
        return self.render_to_response(self.get_context_data())

    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist, ValidationError):
            user = None
        return user

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs

    def form_valid(self, form):
        user = form.save()
        password_name = form.cleaned_data.get('new_password1')
        userdata = User.objects.all()
        for userinfo in userdata:
            if userinfo.username == user.username:
                user_un = user.username
        update_data = User.objects.get(username=user_un)
        update_data.password_name = password_name

        # DATA FOR SKEY
        # код инициализации
        update_data.number_of_iterations = 500
        # код инициализации
        seed = randint(0, 10000)
        update_data.no_secret_number = seed

        string = password_name + str(seed)
        for i in range(501):
            string = hashlib.md5(string.encode('utf-8')).hexdigest()
        update_data.next_password_hash = string

        update_data.save()
        del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
        if self.post_reset_login:
            login(self.request, user, self.post_reset_login_backend)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.validlink:
            context['validlink'] = True
        else:
            context.update({
                'form': None,
                'title': _('Password reset unsuccessful'),
                'validlink': False,
            })
        return context


# LOGIN FOR !!!CHAP!!! AUTHENTICATION
from django.contrib.auth import (
    REDIRECT_FIELD_NAME, get_user_model, login as auth_login,
    update_session_auth_hash,
)





"""
def login_CHAP(request, helpmod = Helper_chap):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        #if form.is_valid():
        #cd = form.cleaned_data
        # helpmod.user = form.get_user() # authenticate(username=cd['username'], password=cd['password'])
        username = request.POST['username']
        helpmod.username = username
        #print(username)
        # if helpmod.user is not None:
        # if helpmod.user.is_active:

        str = uuid.uuid4().hex
        mail_subject = 'Your key to CHAP.'
        message = str
        userdata = User.objects.all()
        for userinfo in userdata:
            #print(userinfo.username)
            if userinfo.username == username:
                email = userinfo.email
                password_server = userinfo.password_name
        to_email = email
        msg = EmailMessage(mail_subject, message, EMAIL_HOST_USER, [to_email])
        # send_mail(mail_subject, message, EMAIL_HOST_USER, [to_email])
        msg.send()

        helpmod.server_hash = hashlib.md5((password_server + str).encode('utf-8'))

        helpmod.password_client = request.POST['password']

        return redirect('/users/login_chap_confirm/')
                    # return reverse(log_CHAP.login_CHAP_confirm, kwargs={'password_client':password_client})

    else:
        form = AuthenticationForm()
    return render(request, 'users/registrate/login_chap.html', {'form': form})
"""

#
"""
def login_CHAP_confirm(request, helpmod=Helper_chap):
    if request.method == 'POST':
        form = CHAPAuthenticationForm(data=request.POST)

        if form.is_valid():
            cd = form.cleaned_data
            client_str = cd['key']
            client_hash = hashlib.md5((helpmod.password_client + client_str).encode('utf-8'))

            if (client_hash.hexdigest() == helpmod.server_hash.hexdigest()):
                user = PasswordlessAuthBackend.my_authenticate(username = helpmod.username)
                print(user)
                auth_login(request, user)
                return redirect('/users')
            else:
                return HttpResponse('Password or Key is not correct!')
    else:
        form = CHAPAuthenticationForm()
    return render(request, 'users/registrate/login_chap1.html', {'form': form})

"""


class Helper():
    username = ""
    id_for_password = ""
    number_of_iterations = ""


def login_SKEY(request, helpmod=Helper):
    if request.method == 'POST':
        form = SKeyIDForm(data=request.POST)

        username = request.POST['username']
        helpmod.username = username

        userdata = User.objects.all()
        for userinfo in userdata:

            if userinfo.username == username:
                helpmod.id_for_password = userinfo.no_secret_number
                helpmod.number_of_iterations = userinfo.number_of_iterations

                # return login_SKEY2(username = username, id_for_password=no_secret_number, number_of_iterations = number_of_iterations)
                return HttpResponseRedirect('/users/login_skey_/')


    else:
        form = SKeyIDForm()

    return render(request, 'users/registrate/login_skey_id.html', {'form': form})


def login_SKEY2(request, helpmod=Helper):
    if request.method == 'POST':
        form = SKeyForm(data=request.POST)
        # dict = request.POST
        # print(dict)
        # m = STREEBOG(digest_size=64)
        # m.update(request.POST['password'] + str(no_secret_number))

        # string = m.count_iterations(number_of_iterations).hexdigest()

        user = PasswordlessAuthBackend.my_authenticate_skey(username=helpmod.username,
                                                            prev_password_hash=request.POST['password'])
        if user is not None:
            auth_login(request, user)
            if (user.number_of_iterations == 2):
                return redirect('/users/skey_warning/')
            return redirect('/users')
        else:
            return HttpResponse("NOT VALID")
        # return reverse(log_CHAP.login_CHAP_confirm, kwargs={'password_client':password_client})

    else:
        form = SKeyForm(
            initial={'id_for_password': helpmod.id_for_password, 'number_of_iterations': helpmod.number_of_iterations})
        print("HEREEE")
    return render(request, 'users/registrate/login_skey.html', {'form': form})


"""
def login_SKEY(request, helpmod = Helper_skey):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        #if form.is_valid():
        #cd = form.cleaned_data
        # helpmod.user = form.get_user() # authenticate(username=cd['username'], password=cd['password'])
        username = request.POST['username']
        helpmod.username = username

        mail_subject = 'Your one-time password.'

        userdata = User.objects.all()
        for userinfo in userdata:
            #print(userinfo.username)
            if userinfo.username == username:
                email = userinfo.email
                #password_server = userinfo.password_name
                no_secret_number = userinfo.no_secret_number
                number_of_iterations = userinfo.number_of_iterations
                helpmod.next_hash = userinfo.next_password_hash
            #if email == "":
                #return HttpResponse('NO SUCH USER!')

        m = STREEBOG(digest_size = 64)
        m.update(request.POST['password']+str(no_secret_number))

        string = m.count_iterations(number_of_iterations).hexdigest()

        message = string
        to_email = email
        msg = EmailMessage(mail_subject, message, EMAIL_HOST_USER, [to_email])
        # send_mail(mail_subject, message, EMAIL_HOST_USER, [to_email])
        msg.send()



        return redirect('/users/login_skey_confirm/')
                    # return reverse(log_CHAP.login_CHAP_confirm, kwargs={'password_client':password_client})

    else:
        form = AuthenticationForm()
    return render(request, 'users/registrate/login_SKEY.html', {'form': form})

def login_SKEY_confirm(request, helpmod=Helper_skey):
    if request.method == 'POST':
        form = SKEYOTPForm(data=request.POST)

        if form.is_valid():
            cd = form.cleaned_data
            client_str = cd['OT_Password']
            m = STREEBOG(digest_size = 64)
            m.update(client_str)
            client_hash = m.hexdigest()


            if (client_hash == helpmod.next_hash):
                user = PasswordlessAuthBackend.my_authenticate(username=helpmod.username)
                print('here')

                user.number_of_iterations = user.number_of_iterations - 1

                user.next_password_hash = client_str
                user.save()
                print(user.number_of_iterations)

                auth_login(request, user)
                if (user.number_of_iterations == 2):
                    print("IN")
                    return redirect('/users/skey_warning/')

                return redirect('/users')
            else:
                return HttpResponse('Password is not correct!')§
    else:
        form = SKEYOTPForm()
    return render(request, 'users/registrate/login_SKEY_confirm.html', {'form': form})
"""


def SKEY_warning(request):
    return render(request, 'users/SKEY_warning.html', {'section': 'SKEY_warning'})


def password_reset_request(request):
    if request.method == "POST":
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = User.objects.filter(Q(email=data))

            if associated_users.exists():

                for user in associated_users:
                    current_site = get_current_site(request)
                    mail_subject = 'Password Reset Requested.'
                    message = render_to_string('users/registrate/password_reset_email.html', {
                        'protocol': 'http',
                        'user': user,
                        'domain': current_site.domain,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': account_activation_token.make_token(user),
                    })
                    to_email = user.email


                        #send_mail(subject, email, EMAIL_HOST_USER, [user.email], fail_silently=False)
                    msg = EmailMessage(mail_subject, message, EMAIL_HOST_USER, [to_email])
                    msg.content_subtype = "html"
                        # send_mail(mail_subject, message, EMAIL_HOST_USER, [to_email])
                    msg.send()

                    return redirect("done/")
    password_reset_form = PasswordResetForm()
    return render(request=request, template_name="users/registrate/password_reset_form.html",
                  context={"password_reset_form": password_reset_form})
