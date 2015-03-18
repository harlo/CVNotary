#! /bin/bash

# Create virtualenv
virtualenv venv
pip install -r requirements.txt
cd lib/camera-v && ./install.sh