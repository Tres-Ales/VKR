from django.conf.urls import url
from django.contrib.auth import views as auth_views, get_user_model

from . import views

import sys


sys.path.append('/course_work/cwork/blog')
from blog import views as bviews

User = get_user_model()

def profile_view(request, username):
    u = User.objects.get(username=username)

urlpatterns = [
    # LOGIN / LOGOUT
    url(r'login/$', views.login, name = 'login'),#auth_views.LoginView.as_view(template_name='users/registrate/login.html'), name = 'login'),

    url(r'login/Know/$', views.Know, name='knowledge'),

    #url(r'login_chap_confirm/$', views.login_CHAP_confirm, name = 'login_CHAP_confirm'),

    url(r'login_skey/$', views.login_SKEY, name = 'login_skey'),
    url(r'login_skey_/$', views.login_SKEY2, name = 'login_skey_'),
    url(r'skey_warning/$', views.SKEY_warning, name = 'SKEY_warning'),

    url(r'logout/$', auth_views.LogoutView.as_view(template_name='users/registrate/logged_out.html'), name='logout'),
    url(r'^$', views.dashboard, name='dashboard'),

    # POST_LIST -> BLOG
    url(r'^blog/$', bviews.post_list, name='post_list'),
    url(r'^users/blog/(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})/'\
        r'(?P<post>[-\w]+)/$',
        bviews.post_detail,
        name='post_detail'),
    url(r'^blog/create/$', bviews.create_post, name='create_post'),

    # CHANGE PASSWORD
    url(r'^password_change/', views.change_password, name='password_change'),#auth_views.PasswordChangeView.as_view(template_name='users/registrate/password_change_form.html'), name= 'password_change'),
    url(r'^password_change/done/', auth_views.PasswordChangeDoneView.as_view(template_name='users/registrate/password_change_done.html'), name='password_change_done'),

    # RESET PASSWORD
    url(r'^password-reset/$', views.password_reset_request, name = 'password_reset'), #auth_views.PasswordResetView.as_view(template_name='users/registrate/password_reset_form.html'), name='password_reset'),
    url(r'^password-reset/done/$', auth_views.PasswordResetDoneView.as_view(template_name='users/registrate/password_reset_done.html'), name='password_reset_done'),
    url(r'^password-reset/confirm/(?P<uidb64>[-\w]+)/(?P<token>[-\w]+)/$', views.PasswordResetConfirmView.as_view(template_name='users/registrate/password_reset_confirm.html'), name='password_reset_confirm'),
    url(r'^password-reset/complete/$', auth_views.PasswordResetCompleteView.as_view(template_name='users/registrate/password_reset_complete.html'), name='password_reset_complete'),

    # SIGN UP
    url(r'^sign-up/choices/', views.choose, name='choices'),
    url(r'^sign-up/', views.signup, name='sign_up'),
    url(r'^confirm/(?P<uidb64>[-\w]+)/(?P<token>[-\w]+)/', views.activate, name ='activate'),
]