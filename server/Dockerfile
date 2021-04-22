FROM public.ecr.aws/lambda/python:3.8

COPY app.py   ./
COPY DatabaseUtils.py   ./
COPY ServerUtils.py   ./
COPY Dockerfile   ./
COPY requirements.txt   ./

CMD ["app.handler"]