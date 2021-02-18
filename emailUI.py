from flask import Flask, render_template, request, redirect, jsonify, session
from flask_session import Session
from emailClass import *
from domainClass import *
import zipfile
import extract_msg
from graphFunc import *
from time import sleep
import copy

from trainer import rfTrain
#flask initialization
webapp = Flask(__name__)
webapp.config['SECRET_KEY'] = b'CSABOLEH'
webapp.config['SESSION_TYPE'] = 'filesystem'
webapp.config['MAX_CONTENT_LENGTH'] = 128 * 1024 * 1024    # 128 Mb limit
Session(webapp)

#Global variables to be used
allowed_files = ["txt", "eml", "msg"]
email_nav = ["Overview", "Relay Tracing", "External Links", "View Raw"]
loading_status = ""
dataframe = None

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
    global loading_status
    session['error_list'] = []

    if request.method == "POST":
        file = request.files['emailfile']
        file_check = check_files(file.filename.lower())
        if file_check == 1:
            session['email_list'] = []
            try:
                if file.filename.split(".")[-1].lower() == allowed_files[2]:
                    msg_file = extract_msg.Message(file, overrideEncoding='utf-8')
                    raw_file = msg_file.header.as_string() + msg_file.body
                elif file.filename.split(".")[-1].lower() in allowed_files:
                    raw_file = file.read().decode("utf-8")
                else:
                    session['error_list'].append(file.filename)
                session['email_list'].append(EmailParser(raw_file))
            except:
                return render_template("/upload.html", err="Unknown file received, upload failed!")

            return redirect("/")
        elif file_check == 2:
            session['email_list'] = []
            try:
                zip_file = zipfile.ZipFile(file)
            except:
                return render_template("/upload.html", err="Unknown file received, upload failed!")
            files = zip_file.namelist()
            for file in files:
                print(file)
                loading_status = file
                try:
                    if file.split(".")[-1].lower() == allowed_files[2]:
                        msg_file = extract_msg.Message(zip_file.open(file), overrideEncoding='utf-8')
                        raw_file = msg_file.header.as_string() + msg_file.body
                    elif file.split(".")[-1].lower() in allowed_files:
                        raw_file = zip_file.open(file).read().decode("utf-8")
                    else:
                        session['error_list'].append(file)

                except Exception as e:
                    session['error_list'].append(file)
                    continue
                try:
                    session['email_list'].append(EmailParser(raw_file))
                except Exception as e:
                    session['error_list'].append(file)
            return redirect("/")
        else:
            return render_template("/upload.html", err="Unknown file received, upload failed!")
    else:
        return render_template("upload.html")

#Main dashboard page
@webapp.route('/', methods=["GET"])
def main_page():
    if not session.get('email_list'):
        return redirect("/upload")
    else:
        month_dict = {}
        for mail in session['email_list']:
            time = pd.Timestamp(mail.date)
            month = time.month
            year = time.year
            datetime = (year, month, 1)

        ordered_list = ["Very Likely", "Likely", "Neutral", "Unlikely", "Very Unlikely"]
        tag_list = [mail.get_phishtag() for mail in session['email_list']]
        tag_dict = {tag: tag_list.count(tag) for tag in tag_list}
        tag_values = sorted(tag_dict.items(), key=lambda pair: ordered_list.index(pair[0]))

        return render_template("index.html", tag_dict=tag_values, total_errors=session['error_list'], total_emails=len(session['email_list']), date_graph=Markup(get_date_plot(session['email_list'])), type_pie=Markup(get_dist(session['email_list'])))

#Email list page
@webapp.route('/email', methods=["GET"])
def email_page():
    if not session.get('email_list'):
        return redirect("/upload")
    elif request.args.get("id") is None:
        return render_template("emaillist.html", emails=session['email_list'])
    else:
        try:
            email_id = int(request.args.get("id"))
        except:
            return redirect("/")
        return render_template("email.html", email=session['email_list'][email_id], email_nav=email_nav, email_id=email_id)

@webapp.route('/email/external_links', methods=['GET'])
def external_link():
    if not session.get('email_list'):
        return redirect("/upload")
    else:
    # try:
        email_id = int(request.args.get("id"))
        select_email = copy.deepcopy(session['email_list'][int(email_id)])
        if select_email.urlextract is False:
            select_email.get_urls()
            select_email.unique_url_ips()
    # except Exception as e:
    #     print("Error occured at email UI: " + str(e))
        redirect("/")
    return render_template('links.html', email=select_email, email_nav=email_nav, email_id=email_id)

@webapp.route('/email/relay_tracing', methods=['GET'])
def relay_trace():
    if not session.get('email_list'):
        return redirect("/upload")
    # else:
    #     try:
    email_id = int(request.args.get("id"))
    select_email = session['email_list'][int(email_id)]
    ip_list = select_email.recv_ips
    for domain, ip in ip_list:
        if ip is not None and not ip.queried and ip.public:
            ip.get_info()
        # except:
        #     return "Don't try and mess with the system"
    return render_template('relay.html', email=session['email_list'][email_id], email_nav=email_nav, email_id=email_id)

@webapp.route('/email/view_raw', methods=['GET'])
def view_raw():
    if not email:
        return redirect("/upload")
    else:
        try:
            email_id = int(request.args.get("id"))
        except:
            redirect("/")
    return render_template('raw.html', email=session['email_list'][email_id], email_nav=email_nav, email_id=email_id)

@webapp.route('/rf', methods=['GET'])
def rf():
    global dataframe
    email_type = request.args.get("type")
    if dataframe is None:
        print(dataframe)
        dataframe = rfTrain.create_df(session['email_list'], email_type)
    else:
        dataframe = dataframe.append(rfTrain.create_df(session['email_list'], email_type))
        print(dataframe)
    return "OK"


@webapp.route('/rftrain')
def rftrain():
    dataframe.to_pickle('emails.pickle')
    return "OK"


@webapp.route('/api/analyze', methods=['POST'])
def api_analyze():
    if request.args.get['emailfile'] is not None:
        file = request.files['emailfile']
        if file.filename not in allowed_files:
            return 403

if __name__ == "__main__":
    webapp.run(host="127.0.0.1", debug=True)
    


