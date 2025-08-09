FROM python:3-alpine

COPY requirements.txt .
RUN apk add --no-cache --virtual .build-deps gcc musl-dev openssl-dev \
    && pip install -r /requirements.txt \
    && apk del .build-deps

COPY *.py .
ENTRYPOINT [ "python3" ]
CMD ["/run.py", "anystr"]

# build
#docker build -t ygg_updater .
# run
#docker run -t --network=host ygg_updater /run.py key
