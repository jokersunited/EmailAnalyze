from collections import defaultdict
from nltk.corpus import wordnet as wn

from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from nltk import pos_tag
from nltk.corpus import stopwords

from sklearn.metrics import plot_confusion_matrix

import pandas as pd
import numpy as np
import io
import base64

import matplotlib.pyplot as plt

tag_map = defaultdict(lambda: wn.NOUN)

tag_map['J'] = wn.ADJ
tag_map['V'] = wn.VERB
tag_map['R'] = wn.ADV
#
# for word, tag in pos_tag(["I", "love", "adding", "cream", "to", "food"]):
#     print(word + " -> " + tag)

def remove_punct(word):
    get_alpha = list([val for val in word if val.isalpha()])
    result = "".join(get_alpha)
    return result

def word_tag():
    tag_map = defaultdict(lambda: wn.NOUN)

    tag_map['J'] = wn.ADJ
    tag_map['V'] = wn.VERB
    tag_map['R'] = wn.ADV

    return tag_map


def load_dataset(filepath, output, truncate=False):
    if not truncate:
        email_df = pd.read_csv(filepath, dtype=str)
    else:
        email_df = pd.read_csv(filepath, dtype=str)[truncate[0]:truncate[1]]
    email_df['email'].dropna(inplace=True)
    email_df['email'] = [word_tokenize(str(row).lower()) for row in email_df['email']]

    tag_map = word_tag()

    for index, text in enumerate(email_df['email']):
        print("[+] Processing row " + str(index) + "!")
        clean_words = []

        word_lem = WordNetLemmatizer()
        for word, tag in pos_tag(text):
            word = remove_punct(word)
            if word.isdigit():
                word = "number"

            if word not in stopwords.words('english') and word.isalpha():
                clean_word = word_lem.lemmatize(word, tag_map[tag[0]])
                clean_words.append(str(clean_word))
        if not truncate:
            email_df.loc[index, 'clean_text'] = str(clean_words)
        else:
            email_df.loc[index+truncate, 'clean_text'] = str(clean_words)

    email_df.to_pickle(output)


def convert_text(text_list, tfidf):
    clean_df = pd.DataFrame(columns=["clean_words"])

    for index, text in enumerate(text_list):
        # print("\n[*] Entry " + str(index))
        # print(text)

        clean_words = []
        tag_map = word_tag()
        word_lem = WordNetLemmatizer()
        for word, tag in pos_tag(text):
            word = word.lower()
            if word not in stopwords.words('english') and word.isalpha():
                clean_word = word_lem.lemmatize(word, tag_map[tag[0]])
                clean_words.append(str(clean_word))

        clean_df.loc[index, 'clean_words'] = str(clean_words)

    return clean_df