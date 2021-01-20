#!/bin/sh
gunicorn --chrdir app emailUI:webapp -w 2 --threads 2 -b 0.0.0.0:8000