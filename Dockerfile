FROM python:3.8
COPY requirements.txt /
RUN pip3 install -r /requirements.txt
COPY . /app
WORKDIR /app
RUN chmod +x /app/deploy.sh
RUN cp install/confusables.json /usr/local/lib/python3.8/site-packages/homoglyphs/confusables.json
RUN cp install/core.py /usr/local/lib/python3.8/site-packages/homoglyphs/core.py
ENTRYPOINT ["./deploy.sh"]