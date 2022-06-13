from . import Classifier
from .models import User_interest, Interests, User

# Получение интересов и сравнение для авторизации
def checkToAuth(url_array, username):
    # Classifier.setDictOfKeywords() # запуск заполнения базы данных ключевых слов
    gotted_dict = Classifier.GetInterests(url_array)
    array_result = []
    # Получаем имена интересов списком
    for elem in gotted_dict.keys():
        if gotted_dict[elem] >= 2:
            array_result.append(elem)

    a = list(User.objects.filter(username = username).values_list('id', flat=True))[0]
    # Получаем интересы из БД для данного пользователя
    list_of_interests = list(User_interest.objects.filter(username=a).values_list('interest', flat=True))
    list_interest = []
    for i in list_of_interests:
        list_interest.append(list(Interests.objects.filter(id=i).values_list('content', flat=True))[0])

    # Сравниваем - возвращается да/нет меньше ли порога несоответствия
    return CompareArrays(list_interest, array_result)

def CompareArrays(arr_db, arr_now, percentage = 0.6):
    k = 0
    for i in arr_db:
        if arr_now.count(i) != 0:
            k += 1
    if k/len(arr_db) < percentage:
        return False
    else:
        return True

# Добавление интересов при регистрации пользователя
def setInterestsRegistration(url_array, username):
    gotted_dict = Classifier.GetInterests(url_array)
    array_result = []
    # Получаем имена интересов списком
    for elem in gotted_dict.keys():
        if gotted_dict[elem] >= 2:
            array_result.append(elem)
    a = list(User.objects.filter(username=username).values_list('id', flat=True))[0]
    # Добавляем полученные интересы
    for ar in array_result:
        arid = list(Interests.objects.filter(content=ar).values_list('id', flat=True))[0]
        User_interest.objects.create(username_id=a, interest_id=arid)