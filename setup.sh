#! /bin/bash

# Create virtualenv
virtualenv venv
pip install -r dutils/requirements.txt
cd lib/camera-v && ./install.sh