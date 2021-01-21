FROM python:3.8-slim
COPY ../requirements.txt /
RUN pip3 install -r /requirements.txt
COPY .. /app
WORKDIR /app
RUN chmod +x /app/docker/deploy.sh
ENTRYPOINT ["./docker/deploy.sh"]