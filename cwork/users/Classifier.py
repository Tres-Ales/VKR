import ratelim as ratelim
import requests
import re
from bs4 import BeautifulSoup
import pandas as pd
from nltk import PorterStemmer, word_tokenize
from nltk.corpus import stopwords
import pymorphy2
from nltk.stem import SnowballStemmer
from sklearn.svm import LinearSVC

from .models import Interests, Keywords

# Данные для обучения: определяем стоп-слова, функцию лемматизации и стемминга
stop_words = stopwords.words("russian")

snowball = SnowballStemmer(language="russian")

morph = pymorphy2.MorphAnalyzer()

# Необходимые датафреймы
URLParse_df = pd.DataFrame(columns=['currUrl', 'response_text'])
Test_df = pd.DataFrame(columns=['class_name', 'keywords'])


@ratelim.patient(1, 1)
# Запуск обработки веб-страницы по URL - адресу
def getPageText(URL):
    try:
        response = requests.get(URL)
        response.raise_for_status()
        response_text = executePage(response)
    except requests.exceptions.HTTPError as err:
        pass
    return response_text


# Функция получение слов с веб-страницы (заголовок, ключевые и описание)
# Аргумент - page - request.get
def executePage(page):
    # преобразуем страницу в суп-объект
    soup = BeautifulSoup(page.text, 'html.parser')
    title = ""
    # Получаем заголовок страницы
    if (soup.find('meta', property="og:title") == None):
        try:
            title = soup.find('title').string
        except:
            title = ""
    else:
        title = soup.find('meta', property="og:title")
        title = str(title).split('="')[1].split('" ')[0]

    description = keywords = ""
    # получаем описание и ключевые слова веб-страницы
    for tag1 in soup.findAll('meta'):
        if (tag1.get('name') == "description" or tag1.get('name') == "Description"):
            description = tag1.get('content')
            description = re.sub('\n', ' ', description)
        elif (tag1.get('name') == "keywords" or tag1.get('name') == "Keywords"):
            keywords = tag1.get('content')
    if description == "":
        return ""
    return title + " " + keywords + " " + description

# Для заполнения тестовых данных
"""
# создание тестового датафрейма
Class_1 = ['путешествие', 'вокруг света', 'туризм', 'достопримечательность', 'курорт', 'турист', 'поездка', 'чемодан', 'турпоездка', 'багаж', 'пляж', 'полет', 'карта'] # ПУтешествие
Class_2 = ['РАН', 'профессор', 'медицина', 'врач', 'доктор', 'медицинская справка', 'заболевание', 'болезнь', 'здоровье', 'медицинский институт', 'мяч', 'футбол', 'баскетбол', 'чемпионат', 'лига', 'воллейбол', 'теннис', 'травма', 'вратарь', 'медаль', 'олимпиада','олимпийский', 'стадион', 'фигурное катание'] # медицица
Class_3 = ['Course work', 'Login', 'курсовая работа', 'программа', 'программирование', 'разработка', 'компьютер', 'ноутбук', 'web', 'chrome', 'program', 'develop', 'Java', 'Python', 'JavaScript', 'код']
Class_4 = ['фильм', 'кино', 'компьютерная игра', 'приставка', 'диск', 'хоррор', 'аттракцион', 'горка', 'комедия', 'мюзикл', 'спектакль', 'выставка', 'искусство', 'развлечение', 'развлекаться', 'драма', 'мелодрама', 'опера', 'балет', 'музыка'] # Развлечения
Class_5 = ['политика', 'политический режим', 'президент', 'премьер', 'министр', 'международные отношения', 'санкции', 'спецоперация', 'конфликт'] # политика
dict_interests = {'Путешествия': Class_1, 'Спорт': Class_2, 'Программирование': Class_3, 'Развлечения': Class_4, 'Политика': Class_5}


# Заполнение базы данных ключевых слов
def setDictOfKeywords():
    arr_interests = list(Interests.objects.values_list('id', 'content')) # return [(,),(,)] - list of tuples
    for i in arr_interests:
        # i[0] interest ID
        # i[1] interest name
        for elem in dict_interests[i[1]]:
            Keywords.objects.create(interest_id=i[0], contentkey=elem)
"""

# Получение словаря {<имя интереса> : <массив ключевых слов>} из БД
def getDictOfKeywords():
    dict_keywords = {}
    arr_interests = list(Interests.objects.values_list('id', 'content'))  # return [(,),(,)] - list of tuples
    for i in arr_interests:
        # i[0] interest ID
        # i[1] interest name
        dict_keywords[i[1]] = list(Keywords.objects.filter(interest=i[0]).values_list('contentkey', flat=True))
    print(dict_keywords)
    return dict_keywords

# Создание датафрейма из словаря {<имя интереса> : <массив ключевых слов>}
def addToTestDF(dicts):
    for d in dicts.keys():
        for i in dicts[d]:
            words = word_tokenize(i)
            for word in words:
                if word not in stop_words:
                    class_name, keywords = d, snowball.stem(word)
                    dataList = [class_name, keywords]
                    Test_df.loc[len(Test_df)] = dataList

# Функция предобработки массива текстов
# Стемминг, Лемматизация, Приведение к нормальной форме (для глаголов)
def Predobr(arr):
    arr1 = []
    for sentence in arr:
        words = word_tokenize(sentence)
        str = ""
        for word in words:
            if word not in stop_words:
                str += snowball.stem(morph.parse(word)[0].normal_form) + " "
        arr1.append(str)
    return arr1

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer



# Получение словаря интересов по URL-адресам, с количеством URL, которые соответствуют определенному интересу
# В качестве параметра - массив URLов
# Возвращает словарь {интерес : количество}
def GetInterests(url_array):
    # Получение начального датасета
    addToTestDF(getDictOfKeywords())
    # Приводим к типу датафрейм
    col = ['class_name', 'keywords']
    df = Test_df[col]
    df = df[pd.notnull(df['keywords'])]
    df.columns = ['class_name', 'keywords']
    df['category_id'] = df['class_name'].factorize()[0]
    category_id_df = df[['class_name', 'category_id']].drop_duplicates().sort_values('category_id')

    # Разделяем датасет на обучающее и тренировочное множество, учим модель
    X_train, X_test, y_train, y_test = train_test_split(df['keywords'], df['class_name'], random_state=0)
    count_vect = CountVectorizer()
    X_train_counts = count_vect.fit_transform(X_train)
    tfidf_transformer = TfidfTransformer()
    X_train_tfidf = tfidf_transformer.fit_transform(X_train_counts)
    clf = LinearSVC().fit(X_train_tfidf, y_train)

    # Получаем массив URL
    array = []
    for i in url_array:
        # Вызываем get_page_text
        array.append(getPageText(i))
    import numpy as np

    # Классификация по построенной модели, массива текстов, полученных при скраппинге
    a = clf.predict(count_vect.transform(Predobr(array)))
    unique, counts = np.unique(a, return_counts=True)
    dict_a = dict(zip(unique, counts))
    dict_a = {k: v for k, v in sorted(dict_a.items(), key=lambda item: item[1], reverse=True)}
    return dict_a

