#! /bin/bash

THIS_DIR=`pwd`

# Create virtualenv
virtualenv venv
source venv/bin/activate

pip install -r requirements.txt

# build camera-v
cd lib/camera-v && ./install.sh

# build j3mparser
cd ../j3mparser
mvn clean install

cd $THIS_DIR
python setup.py "$@"

deactivate venv