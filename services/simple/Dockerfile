FROM python:3-alpine
RUN pip install flask
COPY main.py /main.py
ENTRYPOINT ["/usr/local/bin/python3", "/main.py"]