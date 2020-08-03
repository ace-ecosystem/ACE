import os


class Env:
    """Environment variables passed into container."""
    REDIS_HOST = os.environ.get('REDIS_HOST', '127.0.0.1')
    REDIS_PORT = os.environ.get('REDIS_PORT', 6379)
    REDIS_DB = os.environ.get('REDIS_DB', 0)
    SLEEP = os.environ.get('SLEEP', 5)
    JOB_QUEUE_KEY = os.environ.get('JOB_QUEUE_KEY', 'render:queue:incoming')
