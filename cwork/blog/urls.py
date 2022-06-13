# POST_LIST -> BLOG
from django.conf.urls import url

from . import views

app_name = 'blog'
urlpatterns = [
url(r'^blog/$', views.post_list, name='post_list'),
url(r'^users/blog/(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})/' \
    r'(?P<post>[-\w]+)/$',
    views.post_detail,
    name='post_detail'),
url(r'^blog/create/$', views.create_post, name='create_post'),
]