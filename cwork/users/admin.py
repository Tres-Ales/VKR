from django.contrib import admin

from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin

# Отменить регистрацию предоставленного администратора модели
from .models import Password_params, QA, ManyQuestions, User_interest, Keywords, Interests

#admin.site.unregister(User)
from django.contrib.auth import get_user_model
User = get_user_model()


class PostParams(admin.ModelAdmin):
    list_display = ('namepass', 'length', 'uppercase_symbols', 'number_of_special_symbols', 'number_of_digits')
    list_filter = ('length', 'uppercase_symbols', 'namepass')
    search_fields = ('length', 'uppercase_symbols')

class HowManyQuestions(admin.ModelAdmin):
    list_display = ('questions_all', 'questions_right')
    list_filter = ('questions_all', 'questions_right')
    search_fields = ('questions_all', 'questions_right')

class Users(admin.ModelAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'password_name')
    readonly_fields = ('password', 'password_name')
    list_filter = ('username', 'email')
    search_fields = ('username', 'email')

class QAs(admin.ModelAdmin):
    list_display = ('id_qa', 'interest', 'contentqa', 'answer')
    list_filter = ('interest', 'contentqa')
    search_fields = ('interest', 'contentqa')

class Interestss(admin.ModelAdmin):
    list_display = ('id', 'content')
    list_filter = ('id', 'content')
    search_fields = ('id', 'content')

class User_interests(admin.ModelAdmin):
    list_display = ('username', 'interest')
    list_filter = ('username', 'interest')
    search_fields = ('username', 'interest')

class Keywordss(admin.ModelAdmin):
    list_display = ('id_k', 'interest', 'contentkey')
    list_filter = ('interest', 'contentkey')
    search_fields = ('interest', 'contentkey')

# Register your models here.
admin.site.register(Password_params, PostParams)
admin.site.register(User, Users)
admin.site.register(QA, QAs)
admin.site.register(User_interest, User_interests)
admin.site.register(ManyQuestions, HowManyQuestions)
admin.site.register(Keywords, Keywordss)
admin.site.register(Interests, Interestss)

