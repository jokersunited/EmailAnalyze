#!/bin/sh
docker build -t emailflask/python . --rm
docker run emailflask/python -p 8000:8000