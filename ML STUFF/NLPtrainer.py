import extract_msg
import homoglyphs as hg

import pandas as pd
from nltk.stem.porter import PorterStemmer
from nltk.corpus import stopwords

import os
import string

# from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
# from sklearn.naive_bayes import MultinomialNB
# from sklearn.metrics import classification_report,confusion_matrix, accuracy_score
from sklearn.ensemble import RandomForestClassifier
from sklearn import metrics

# import matplotlib.pyplot as plt
# import seaborn as sns
import pickle

range1 = list(range(ord('a'), ord('z')))
range2 = list(range(ord('A'), ord('Z')))
range3 = [ord('-'), ord('\''), ord("©")]

ascii_range = list(range(0, 128))
ascii_range.append(ord("©"))

# def clean_str_new(s):
#     porter = PorterStemmer()
#     stop_words = set(stopwords.words('english'))
#
#     if (type(s) != str):
#         s = s[0].get_payload()
#         if (type(s) != str):
#             s = s[0].get_payload()
#
#     split_str = s.split()
#     table = str.maketrans(" " * len(string.punctuation), string.punctuation)
#     lower_str = [porter.stem(s2.translate(table).lower()) for s2 in split_str if len(s2) < 15 and len(s2) > 2 and s2.translate(table).isalpha() and s2.translate(table).lower() not in stop_words]
#     return lower_str
#
# def check_homo(body):
#     for letter in body:
#         if ord(letter) not in ascii_range:
#             return True
#         else:
#             continue
#     return False
#
# def check_word(word):
#     for letter in word:
#         if ord(letter) > ord("z") or ord(letter) < ord('a'):
#             return False
#         else:
#             continue
#     return True
#
# basepath = "E:\\Coding Projects\\Intern CSA\\NLPtrainer\\emails"
#
# def clean_email(filepath):
#     f = extract_msg.Message(filepath)
#     list_body = f.body.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').replace('.', ' ').replace(',', ' ').split(" ")
#
#     word_list = []
#
#     if check_homo(f.body):
#         homoglyphs = hg.Homoglyphs(languages={'en'},
#             strategy=hg.STRATEGY_LOAD,
#             ascii_strategy=hg.STRATEGY_REMOVE,
#             ascii_range= range1 + range2 + range3)
#
#         for word in list_body:
#             if word == "" or len(word) > 15:
#                 continue
#             elif word[0] == "I":
#                 continue
#             else:
#                 clean_word = homoglyphs.to_ascii(word)
#                 if clean_word != []:
#                     if clean_word[0].isupper():
#                         clean_word = clean_word[0].lower()
#                     else:
#                         clean_word = clean_word[-1].lower()
#                     if not'-' in clean_word:
#                         word_list.append(clean_word)
#                     else:
#                         clean_word = clean_word.split('-')
#                         word_list.extend(clean_word)
#                 else:
#                     continue
#
#     else:
#         for word in list_body:
#             new_word = word.replace('\n', '').replace('\r', '').replace('\t', '').replace('.', '').replace(',', '')
#             if new_word == '':
#                 continue
#             else:
#                 lower_word = new_word.lower()
#                 if not check_word(lower_word):
#                     continue
#                 else:
#                     word_list.append(new_word.lower())
#
#     return word_list

# list_matrix = []

# for filename in os.listdir(basepath):
#     print("\n\n" + filename)
#     if filename.endswith('.msg'):
#         word_list = clean_email(os.path.join(basepath, filename))
#         data = " ".join(word_list)
#         list_matrix.append([clean_str_new(data), 1])
        
#     else:
#         continue

# def dummy(doc):
#     return doc

#training data
df_good = pd.read_pickle("./good.pkl")
df_bad = pd.read_pickle("./bad.pkl")

data = pd.concat([df_good, df_bad])

with pd.option_context('display.max_rows', None, 'display.max_columns', None):  # more options can be specified also
        print(data)

X=data[['spf','dkim','dmarc','domain','iplink','homo','word_payment','word_account', 'word_postal']]  # Features
y=data['type']  # Labels

# Split dataset into training set and test set
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2) # 70% training and 30% test

clf=RandomForestClassifier(n_estimators=1000)
clf.fit(X,y)

filehandler = open("model.pkl", 'wb')
pickle.dump(clf, filehandler)


y_pred=clf.predict(X_test)

print(y_pred)
print(y_test.values)
print("Accuracy:",metrics.accuracy_score(y_test, y_pred))

# feature_imp = pd.Series(clf.feature_importances_,index=['spf','dkim','dmarc','domain','iplink','homo','word_payment','word_account', 'word_postal']).sort_values(ascending=False)
# print(feature_imp)
#
# sns.barplot(x=feature_imp, y=feature_imp.index)
# plt.xlabel('Feature Importance Score')
# plt.ylabel('Features')
# plt.title("Visualizing Important Features")
# plt.legend()
# plt.show()

# cv_train = CountVectorizer(tokenizer=dummy,preprocessor=dummy)
# data_cv_train = cv_train.fit_transform(df_train['Content'])
# data_dtm_train = pd.DataFrame(data_cv_train.toarray(), columns=cv_train.get_feature_names())

# #testing data
# df_test = pd.DataFrame(list_matrix, columns=["Content","Spam"])
# # cv_test = CountVectorizer(stop_words="english", analyzer='word')
# data_cv_test = cv_train.transform(df_test['Content'])
# data_dtm_test = pd.DataFrame(data_cv_test.toarray(), columns=cv_train.get_feature_names())
# print(cv_train.get_feature_names())
# print(data_dtm_test)
# print(data_dtm_train)
# # print(data_cv)
# # print(df['Spam'])

# # X_train, X_test, y_train, y_test = train_test_split(data_cv, df['Spam'], test_size = 0.20, random_state = 0)
# classifier = MultinomialNB()
# classifier.fit(data_cv_train, df_train['Spam'])

# # X_train, X_test, y_train, y_test = train_test_split(data_cv_train, df_train['Spam'], test_size = 0.40, random_state = 42)

# # classifier.fit(X_train, y_train)

# # pred = classifier.predict(X_train)
# # print(pred)
# # print(classification_report(y_train ,pred))
# # print('Confusion Matrix: \n', confusion_matrix(y_train,pred))
# # print('\n')
# # print('Accuracy: ', accuracy_score(y_train,pred))

# # pred = classifier.predict(X_test)
# # #Print the predictions
# # print('\n\n\nPredicted value: ', pred)
# # #Print Actual Label
# # print('Actual value: ', y_test.values)
# # print('Accuracy: ', accuracy_score(y_test,pred))

# pred = classifier.predict(data_cv_train)
# print(pred)
# print(classification_report(df_train['Spam'] ,pred))
# print('Confusion Matrix: \n', confusion_matrix(df_train['Spam'],pred))
# print('\n')
# print('Accuracy: ', accuracy_score(df_train['Spam'],pred))

# pred = classifier.predict(data_cv_test)
# #Print the predictions
# print('\n\n\nPredicted value: ', pred)
# #Print Actual Label
# print('Actual value: ', df_test['Spam'].values)
# print('Accuracy: ', accuracy_score(df_test['Spam'],pred))

# # data_dtm.index = df.Title
# # print(data_dtm)