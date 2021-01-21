from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from xgboost import XGBClassifier, XGBRFClassifier
from sklearn import metrics
import pandas as pd

goodspf = ['PASS']
badspf = ['FAIL', 'SOFTFAIL', 'TEMPERROR', 'PERMERROR']

def check_value(type, email):
    score = 0
    if type == 0:
        for value in email.checks.values():
            for check in value:
                if check[0].lower() == 'spf':
                    if check[2] in goodspf:
                        score += 1
                    elif check[2] in badspf:
                        score += -2
                    else:
                        continue
    elif type == 1:
        for value in email.checks.values():
            for check in value:
                if check[0].lower() == 'dkim':
                    if check[2] in goodspf:
                        score += 1
                    elif check[2] in badspf:
                        score += -2
                    else:
                        continue
    elif type == 2:
        for value in email.checks.values():
            for check in value:
                if check[0].lower() == 'dmarc':
                    if check[2] in goodspf:
                        score += 1
                    elif check[2] in badspf:
                        score += -2
                    else:
                        continue
    elif type == 3:
        for value in email.checks.values():
            print(value)
            for check in value:
                if check[0].lower() == 'domain alignment':
                    print(check[2])
                    if check[2] in goodspf:
                        score += 1
                    elif check[2] in badspf:
                        score += -1
                    else:
                        continue
    return score

def create_df(email_list, type):
    data = pd.DataFrame({
        'blacklist': [len(email.black) for email in email_list],
        'confidence': [float(email.confidence) if email.phish == 1 else -float(email.confidence) for email in email_list],
        'spf': [check_value(0, email) for email in email_list],
        'dkim': [check_value(1, email) for email in email_list],
        'dmarc': [check_value(2, email) for email in email_list],
        'alignment': [check_value(3, email) for email in email_list],
        'homo': [email.homo for email in email_list],
        'money': [email.word_dict['money'][0] * (1 + email.word_dict['scare'][0] + email.word_dict['urgency'][0]) / email.word_dict['length'] for email in email_list],
        'credentials': [email.word_dict['credentials'][0] * (1 + email.word_dict['scare'][0] + email.word_dict['urgency'][0]) / email.word_dict['length'] for email in email_list],
        'postal': [email.word_dict['postal'][0] * (1 + email.word_dict['scare'][0] + email.word_dict['urgency'][0]) / email.word_dict['length'] for email in email_list],
        'type': type
    })
    return data

def rf_train():
    for i in range(0, 20):
        df = pd.read_pickle('C:/Users/jshww/Documents/InternCSA2/IWSP CSA/EmailAnalyze/emails.pickle')
        X_train, X_test, y_train, y_test = train_test_split(df[[col for col in df.columns if col not in ['type', 'svm']]], df['type'], test_size=0.3)

        # Create a Gaussian Classifier
        clf = RandomForestClassifier(n_estimators=200, verbose=False)
        lrg = LogisticRegression(max_iter=1200000)
        knn = KNeighborsClassifier(n_neighbors=8)
        gboost = GradientBoostingClassifier(n_estimators=200)
        xgboost = XGBClassifier()
        xgboostrf = XGBRFClassifier(n_estimators=200)

        # xgboost.fit(X_train, y_train)
        # y_pred = xgboost.predict(X_test)
        # accuracy = str(metrics.accuracy_score(y_test, y_pred))
        #
        # print("XGBOOST: " + accuracy)
        #
        # feature_imp = pd.Series(xgboost.feature_importances_,
        #                         index=[col for col in df.columns if col not in ['type', 'svm']]).sort_values(
        #     ascending=False)
        # print(feature_imp)

        # xgboostrf.fit(X_train, y_train)
        # y_pred = xgboostrf.predict(X_test)
        # accuracy = str(metrics.accuracy_score(y_test, y_pred))
        #
        # print("XGBOOSTRF: " + accuracy)
        #
        # feature_imp = pd.Series(xgboostrf.feature_importances_,
        #                         index=[col for col in df.columns if col not in ['type', 'svm']]).sort_values(
        #     ascending=False)
        # print(feature_imp)

        # gboost.fit(X_train, y_train)
        # y_pred = gboost.predict(X_test)
        # accuracy = str(metrics.accuracy_score(y_test, y_pred))
        #
        # print("GBOOST: " + accuracy)
        #
        # feature_imp = pd.Series(gboost.feature_importances_,
        #                         index=[col for col in df.columns if col not in ['type', 'svm']]).sort_values(ascending=False)
        # print(feature_imp)



        # knn.fit(X_train, y_train)
        # y_pred = knn.predict(X_test)
        # accuracy = str(metrics.accuracy_score(y_test, y_pred))
        #
        # print("KNN(" + str(8) + "):" + accuracy)

        # Train the model using the training sets y_pred=clf.predict(X_test)
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        # Model Accuracy, how often is the classifier correct?
        # print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
        accuracy = str(metrics.accuracy_score(y_test, y_pred))

        print("RNF: " + accuracy)

        print(metrics.classification_report(y_test, y_pred, labels=[0, 1]))
        feature_imp = pd.Series(clf.feature_importances_, index=[col for col in df.columns if col not in ['type', 'svm']]).sort_values(ascending=False)
        print(feature_imp)

        # lrg.fit(X_train, y_train)
        # y_pred = lrg.predict(X_test)
        # accuracy = str(metrics.accuracy_score(y_test, y_pred))
        #
        # print("LGR: " + accuracy)
        exit()

rf_train()