FROM python:3.8.3-slim
COPY requirements.txt /
RUN pip3 install -r /requirements.txt
COPY . /app
WORKDIR /app
RUN chmod +x /app/deploy.sh
ENTRYPOINT ["./deploy.sh"]