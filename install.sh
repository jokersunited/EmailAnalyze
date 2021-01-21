#!/bin/sh
docker build -t emailflask/python . --rm
docker run -p 8000:8000 emailflask/python