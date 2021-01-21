#Email Header Analyzer

**Table of Contents**

[TOCM]

## Features

- SPF, DKIM, DMARC checks
- Domain Alignment checks
- SMTP Relay Tracing with blacklisted IPs
- URL parsing with Domain (WHOIS) & Certificate (HTTPS) checks
- Homoglyph Checks
- Email Categorisation
	- Spoofed
	- Blacklisted
	- Deception
	- Money/Credentials/Scare/Urgency/Postal (Customisable)
- Overall Phishing Score
- Graphical Display

##Installation (Localhost)
Using python3 and flask, a local WSGI server will run locally that provides the user an interface to interact with the application.

###Pre-requisites
Python3 with pip installed

###Steps
Due to some inherent bugs in the homogplyhs package that causes the application to crash, some manual fixing is required.

1. $pip install -r requirements.txt
2. Replace line 111 of C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python38-32\Lib\homoglyphs\core.py with "open(cls.fpath, encoding='utf-8') as f:"
3. Replace confusables.json file at same folder (\homoglyphs) with the file provided in the install folder
4. Run the program using the command line "$python3 emailUI.py"
5. Access the UI through your browser using "http://localhost:5000"
6. Upload your ZIP file with all the email headers using the UI

##Installation (Remote Deployment)
The entire application is delivered through a docker container in a linux enviornment. Gunicorn is used within the docker container as a WSGI for interacting with the flask application. NGINX is used  within the host linux environment to serve as the public facing web server to proxy the traffic to Gunicorn running within the docker container.

While the application can work without the NGINX proxy, Gunicorn on its own is prone to DDoS and the NGINX proxy will serve to filter and only direct appropirate traffic to the gunicorn server which will greatly conserve the amount of resources that Gunicorn uses.

###Pre-requisites
Linux environment with Docker and NGINX (possible to deploy on windows too but not tested)

###Steps
1. git clone entire repository into a folder of your choice
2. run ./install.sh (Remember to give execution rights to the file "chmod +x install.sh")
 	- This step creates the docker image and automatically runs it exposing port 8000
3. Setup NGINX to reverse proxy to port 8000 locally (refer to https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/)