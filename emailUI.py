from flask import Flask, render_template, request, redirect, jsonify
from emailClass import *
import zipfile
import extract_msg
from graphFunc import *

from time import sleep

#flask initialization
webapp = Flask(__name__)
webapp.config['SECRET_KEY'] = 'CSA BOLEH'

#Global variables to be used
allowed_files = ["txt", "eml", "msg"]
email = None
email_list = []
email_nav = ["Overview", "Relay Tracing", "External Links", "View Raw"]
loading_status = ""

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
    global loading_status

    if request.method == "POST":
        file = request.files['emailfile']
        file_check = check_files(file.filename)
        if file_check == 1:
            email_list = []
            loading_status = file.filename
            if file.filename.split(".")[-1] == allowed_files[2]:
                msg_file = extract_msg.Message(file)
                raw_file = msg_file.header.as_string() + msg_file.body
            elif file.filename.split(".")[-1] in allowed_files:
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
                loading_status = file
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

        ordered_list = ["Very Likely", "Likely", "Neutral", "Unlikely", "Very Unlikely"]
        tag_list = [mail.get_phishtag() for mail in email_list]
        tag_dict = {tag: tag_list.count(tag) for tag in tag_list}
        tag_values = sorted(tag_dict.items(), key=lambda pair: ordered_list.index(pair[0]))

        return render_template("index.html", tag_dict=tag_values, total_emails=len(email_list), date_graph=Markup(get_date_plot(email_list)), type_pie=Markup(get_dist(email_list)))

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
            return redirect("/")
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
            redirect("/")
    return render_template('links.html', email=email_list[email_id], email_nav=email_nav, email_id=email_id)

@webapp.route('/email/relay_tracing', methods=['GET'])
def relay_trace():
    if not email:
        return redirect("/upload")
    # else:
    #     try:
    email_id = int(request.args.get("id"))
    select_email = email_list[int(email_id)]
    ip_list = select_email.recv_ips
    for domain, ip in ip_list:
        if ip is not None and not ip.queried and ip.public:
            ip.get_info()
        # except:
        #     return "Don't try and mess with the system"
    return render_template('relay.html', email=email_list[email_id], email_nav=email_nav, email_id=email_id)

@webapp.route('/email/view_raw', methods=['GET'])
def view_raw():
    if not email:
        return redirect("/upload")
    else:
        try:
            email_id = int(request.args.get("id"))
        except:
            redirect("/")
    return render_template('raw.html', email=email_list[email_id], email_nav=email_nav, email_id=email_id)

if __name__ == "__main__":
    webapp.run(host="127.0.0.1", debug=True)
    


