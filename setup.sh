#! /bin/bash

# Create virtualenv
virtualenv venv
pip install -r requirements.txt

# build camera-v
cd lib/camera-v && ./install.sh

# build j3mparser
cd ../j3mparser
mvn clean compile assembly:single
mvn install

# build proofofexistence
cd ../proofofexistence
pip install -r requirements.txt
python setup.py $1