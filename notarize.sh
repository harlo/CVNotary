#! /bin/bash
source venv/bin/activate
python cvnotary.py "$@"
deactivate venv