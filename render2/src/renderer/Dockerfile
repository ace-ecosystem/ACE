FROM selenium/standalone-chrome

USER root

RUN apt-get update && apt-get install -y python3-pip

RUN pip3 install -v --trusted-host=pypi.org \
    --trusted-host=files.pythonhosted.org \
    --trusted-host=pypi.python.org \
    redis selenium

COPY selenium.conf /etc/supervisor/conf.d/
COPY render.py /app/render.py
COPY job_queue.py /app/job_queue.py
COPY enums.py /app/enums.py
COPY env.py /app/env.py
COPY shared_logging.py /app/shared_logging.py
COPY __init__.py /app/__init__.py

COPY renderer-entry.sh /entry/

RUN chown -R seluser:seluser /app \
    && chown -R seluser:seluser /entry \
    && chmod u+x /entry/renderer-entry.sh

USER seluser

CMD ["/bin/bash", "-c"]
ENV PYTHONPATH="/app:${PYTHONPATH}"

ENTRYPOINT ["/entry/renderer-entry.sh"]
