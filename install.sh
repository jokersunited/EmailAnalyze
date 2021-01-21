#!/bin/sh
docker build -t emailflask/python ./docker --rm
docker run emailflask/python