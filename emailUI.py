from flask import Flask, render_template, request, redirect
from emailClass import *
import zipfile
import extract_msg
import webbrowser
import pandas as pd
from graphFunc import *
from flask import Markup

#flask initialization
webapp = Flask(__name__)

#Global variables to be used
allowed_files = ["txt", "eml", "msg"]
email = None
email_list = []
email_nav = ["Overview", "Relay Tracing", "External Links", "View Raw"]

#Check filenames to determine if single file, multiple file or invalid format
def check_files(filename):
    extenstion = filename.split('.')[-1]
    if extenstion == "zip":
        return 2
    elif extenstion in allowed_files:
        return 1
    else:
        return 0

#Upload page
@webapp.route('/upload', methods=["GET", "POST"])
def upload_page():
    global email
    global email_list

    if request.method == "POST":
        file = request.files['emailfile']
        file_check = check_files(file.filename)
        if file_check == 1:
            email_list = []
            if file.filename.split(".")[-1] == allowed_files[2]:
                msg_file = extract_msg.Message(file)
                raw_file = msg_file.header.as_string() + msg_file.body
            elif file.split(".")[-1] in allowed_files:
                raw_file = file.read().decode("utf-8")
            else:
                return render_template("/upload.html", err="File upload failed!")
            email = EmailParser(raw_file)
            email_list.append(email)
            return redirect("/")

        elif file_check == 2:
            email_list = []
            zip_file = zipfile.ZipFile(file)
            files = zip_file.namelist()
            for file in files:
                try:
                    if file.split(".")[-1] == allowed_files[2]:
                        msg_file = extract_msg.Message(zip_file.open(file))
                        raw_file = msg_file.header.as_string() + msg_file.body
                    elif file.split(".")[-1] in allowed_files:
                        raw_file = zip_file.open(file).read().decode("utf-8")
                    else:
                        return render_template("/upload.html", err="File upload failed!")
                except Exception as e:
                    print(e)
                    return render_template("/upload.html", err="File upload failed!")
                email = EmailParser(raw_file)
                email_list.append(email)
            return redirect("/")
        else:
            return render_template("/upload.html", err="File upload failed!")
    else:
        return render_template("upload.html")

#Main dashboard page
@webapp.route('/', methods=["GET"])
def main_page():
    if not email:
        return redirect("/upload")
    else:
        month_dict = {}
        for mail in email_list:
            time = pd.Timestamp(mail.date)
            month = time.month
            year = time.year
            datetime = (year, month, 1)

        clean_list = [mail for mail in email_list if mail.phish == "PASS"]
        phish_list = [mail for mail in email_list if mail.phish == "FAIL"]
        return render_template("index.html", clean_list=clean_list, phish_list=phish_list, date_graph=Markup(get_date_plot(email_list)), type_pie=Markup(get_pie(email_list)))

#Email list page
@webapp.route('/email', methods=["GET"])
def email_page():
    if not email:
        return redirect("/upload")
    elif request.args.get("id") is None:
        return render_template("emaillist.html", emails=email_list)
    else:
        try:
            email_id = int(request.args.get("id"))
        except:
            return "Don't try and mess with the system"
        # if select_email.urlextract is False:
        #     print("GETTING URLS")
        #     select_email.get_urls()
        #     select_email.unique_url_ips()
        #     select_email.urlextract = True
        # for domain, ip in ip_list:
        #     if ip is not None and not ip.queried and ip.public:
        #         ip.get_info()
        print(get_date_plot(email_list))
        return render_template("email.html", email=email_list[email_id], email_nav=email_nav, email_id=email_id)

@webapp.route('/email/external_links', methods=['GET'])
def external_link():
    if not email:
        return redirect("/upload")
    else:
        try:
            email_id = int(request.args.get("id"))
            select_email = email_list[int(email_id)]
            if select_email.urlextract is False:
                print("GETTING URLS")
                select_email.get_urls()
                select_email.unique_url_ips()
                select_email.urlextract = True
        except Exception as e:
            print("Error occured at email UI: " + str(e))
            return "Don't try and mess with the system"
    return render_template('links.html', email=email_list[email_id], email_nav=email_nav, email_id=email_id)

@webapp.route('/email/relay_tracing', methods=['GET'])
def relay_trace():
    if not email:
        return redirect("/upload")
    else:
        try:
            email_id = int(request.args.get("id"))
            select_email = email_list[int(email_id)]
            ip_list = select_email.recv_ips
            for domain, ip in ip_list:
                if ip is not None and not ip.queried and ip.public:
                    ip.get_info()
        except:
            return "Don't try and mess with the system"
    return render_template('relay.html', email=email_list[email_id], email_nav=email_nav, email_id=email_id)

@webapp.route('/email/view_raw', methods=['GET'])
def view_raw():
    if not email:
        return redirect("/upload")
    else:
        try:
            email_id = int(request.args.get("id"))
        except:
            return "Don't try and mess with the system"
    return render_template('raw.html', email=email_list[email_id], email_nav=email_nav, email_id=email_id)

@webapp.route('/consolidate', methods=['GET'])
def consolidate():
    data = []
    columns=['spf','dkim','dmarc','domain','iplink','homo','word_payment','word_account', 'word_postal', 'type']

    goodspf = ['PASS']
    badspf = ['FAIL', 'SOFTFAIL']

    for email in email_list:
        row = [0 for x in columns]
        for value in email.checks.values():
            for check in value:
                if check[0].lower() == 'spf':
                    if check[2] in goodspf:
                        row[0] = 1
                    elif check[2] in badspf:
                        row[0] = -1
                    else:
                        continue
                if check[0].lower() == 'dkim':
                    if check[2] in goodspf:
                        row[1] = 1
                    elif check[2] in badspf:
                        row[1] = -1
                    else:
                        continue
                if check[0].lower() == 'dmarc':
                    if check[2] in goodspf:
                        row[2] = 1
                    elif check[2] in badspf:
                        row[2] = -1
                    else:
                        continue
                if check[0].lower() == 'domain alignment':
                    if check[2] in goodspf:
                        row[3] = 1
                    elif check[2] in badspf:
                        row[3] = -1
                    else:
                        continue
                if check[0].lower() == 'ip address links':
                    if check[2] == 'NO':
                        row[4] = 1
                    else:
                        row[4] = 0
                if check[0].lower() == 'homoglyph percentage' and float(check[2][:-1]) > 0.01:
                    row[5] = 1
        row[6] = email.word_dict['money'][0] * (1 + email.word_dict['scare'][0] + email.word_dict['urgency'][0]) / email.word_dict['length']
        row[7] = email.word_dict['credentials'][0] * (1 + email.word_dict['scare'][0] + email.word_dict['urgency'][0]) / email.word_dict['length']
        row[8] = email.word_dict['postal'][0] * (1 + email.word_dict['scare'][0] + email.word_dict['urgency'][0]) / email.word_dict['length']
        row[9] = int(request.args.get("type"))
        data.append(row)
    print(data)
    consol_df = pd.DataFrame(data, columns=columns)
    with pd.option_context('display.max_rows', None, 'display.max_columns', None):  # more options can be specified also
        print(consol_df)
    consol_df.to_pickle("./" + request.args.get("name") + ".pkl")
    return 'Success!'


if __name__ == "__main__":
    webbrowser.open('http://127.0.0.1:5000', new = 2)
    webapp.run()
    

