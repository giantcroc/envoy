FROM python:3.10-slim-bullseye

ADD requirements.txt /tmp/flask-requirements.txt
RUN export http_proxy=http://child-prc.intel.com:913 && export https_proxy=http://child-prc.intel.com:913 && pip3 install -r /tmp/flask-requirements.txt
RUN mkdir /code

ENTRYPOINT ["python3", "/code/service.py"]
