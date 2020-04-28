FROM python:3.8-alpine
ENV SAQ_HOME /opt/ace
ENV SAQ_USER ace
ENV SAQ_GROUP ace
ENV TZ UTC
RUN addgroup -S $SAQ_GROUP \
    && adduser -G $SAQ_GROUP -S $SAQ_USER -s /bin/bash \
    && apk add \
        bash \
        git \
        curl \ 
        nmap \
        p7zip \
        unzip \
        poppler-utils \
        rng-tools \
        libffi-dev \
        python3-dev \
        libstdc++ \
        g++ \
        openssl \
        make \
        openssl-dev \
        zlib-dev \
        jpeg-dev \
        linux-headers \
        uwsgi \
        uwsgi-python3 \
        libxslt-dev \
    && ln -s /usr/include/locale.h /usr/include/xlocale.h \
    && mkdir /opt/signatures \
    && chown ace:ace /opt/signatures \
    && mkdir /opt/ace \
    && chown ace:ace /opt/ace \
    && python3 -m pip install pip virtualenv --upgrade
USER ace
WORKDIR /opt/ace
COPY --chown=ace:ace docker/provision/ace/python-requirements-3.6.txt docker/provision/ace/python-requirements-3.6.txt
RUN python3 -m virtualenv --python=/usr/bin/python3 /opt/ace/venv \
    && source /opt/ace/venv/bin/activate \
    && python3 -m pip install -r docker/provision/ace/python-requirements-3.6.txt
COPY --chown=ace:ace . /opt/ace
RUN docker/provision/ace/install
