FROM tiangolo/uvicorn-gunicorn-fastapi

RUN pip3 install -v --trusted-host=pypi.org \
    --trusted-host=files.pythonhosted.org \
    --trusted-host=pypi.python.org \
    redis

RUN groupadd -g 999 controller && \
    useradd -r -u 999 -g controller controller
USER controller

COPY controller.py /app/main.py
COPY job_queue.py /app/job_queue.py
COPY enums.py /app/enums.py
COPY env.py /app/env.py
COPY shared_logging.py /app/shared_logging.py
COPY __init__.py /app/__init__.py
