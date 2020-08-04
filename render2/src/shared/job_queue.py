import time
from typing import Optional, Union

import redis

from env import Env
from enums import StatusEnum
from shared_logging import get_logger, truncate, MAX_LENGTH

JOB_KEY_PREFIX = 'render:job:'
EXPIRE_IN_SECONDS = 3600

logger = get_logger(__name__)


def make_job_key(job_id: str) -> str:
    return JOB_KEY_PREFIX + job_id


def filter_empty(input: Union[str, dict]) -> Optional[Union[str, dict]]:
    if len(input) == 0:
        return None
    else:
        return input


class JobQueue:
    """Helper class for interacting with Redis and job hash maps.

    Attributes:
        redis: The Redis object to be used while communicating with Redis.
        job_list_key: The key to the Redis list which contains jobs.
    """
    def __init__(self, redis_object: redis.Redis=None, job_list_key: str=None):
        self.redis = redis_object or redis.Redis(
            Env.REDIS_HOST, Env.REDIS_PORT, Env.REDIS_DB, decode_responses=True, encoding='utf-8', socket_timeout=10
        )
        self.job_list_key = job_list_key or Env.JOB_QUEUE_KEY
        logger.info(f'successfully initialized JobQueue! Host: {Env.REDIS_HOST}, Port: {Env.REDIS_PORT}, DB: {Env.REDIS_DB}')

    @property
    def pending_jobs(self):
        pass

    @pending_jobs.getter
    def pending_jobs(self):
        return self.redis.llen(self.job_list_key)

    def add_job(self, job: dict):
        job_id = job['id']
        job_key = make_job_key(job_id)

        try:
            # add the job to redis as a hash
            self.redis.hset(job_key, mapping=job)
            # expire the record if it is not removed in so many seconds
            #   this will protect against a leak where redis grows too
            #   large
            self.redis.expire(job_key, EXPIRE_IN_SECONDS)
            # add the key to the queue
            self.redis.rpush(self.job_list_key, job_id)
            logger.info(f'added job {job_id} to queue')
        except Exception as e:
            logger.error(f'unable to add job {job_id} to queue. {e.__class__}, {e}')

    def remove_job(self, job_id: str):
        job_key = make_job_key(job_id)
        try:
            # remove the hash, if it exists
            self.redis.delete(job_key)
            # remove job from the queue, if it exists
            self.redis.lrem(self.job_list_key, 1, job_key)
            logger.info(f'removed job {job_id} from queue')
        except Exception as e:
            logger.error(f'unable to remove job {job_id} from queue. {e.__class__}, {e}')

    def get_job(self, job_id: str) -> Optional[dict]:
        job_key = make_job_key(job_id)
        try:
            job = filter_empty(self.redis.hgetall(job_key))
            logger.info(f'getting job {job_id} from queue')
            return job
        except Exception as e:
            logger.error(f'unable to get job {job_id} from queue. {e.__class__}, {e}')

    def update_job_value(self, job_id: str, key: str, value: str):
        job_key = make_job_key(job_id)
        _log_value = truncate(value, MAX_LENGTH)
        try:
            self.redis.hset(job_key, key, value)
            logger.info(f'updating job {job_id}\'s property "{key}" to "{_log_value}"')

        except Exception as e:
            logger.error(f'unable to update job {job_id}\'s property "{key}" to "{_log_value}". {e.__class__}, {e}')

    def pop_job(self) -> Optional[str]:
        try:
            job_id = self.redis.lpop(self.job_list_key)
            if job_id:
                logger.info(f'popping job {job_id} from queue')
            return job_id
        except Exception as e:
            logger.error(f'unable to pop job from queue. {e.__class__}, {e}')

    def flush(self):
        return self.redis.flushdb()

class CachedJob:
    """Helper class for getting and manipulating a job that exists in a JobQueue

    The 'wait_for_new_job' method keeps the script/container running until
    a new job has been acquired from the redis queue.

    Attributes:
        job_id: The job id that is pulled from the job queue
    """
    def __init__(self, queue: JobQueue, job_id: str=None):
        self.queue = queue
        self.current_job_id = None

    def wait_for_new_job(self, sleep: int=None) -> None:
        """Check Redis for new jobs.

        Once a new job is popped off the queue, this loop is done.
        """
        _sleep = sleep or 5
        while True:
            current_job_id = self.queue.pop_job()
            if current_job_id is not None:
                logger.info(f'Successfully cached job {current_job_id} from queue')
                break
            time.sleep(sleep)
        self.current_job_id = current_job_id
        return

    @property
    def status(self):
        pass

    @status.getter
    def status(self) -> StatusEnum:
        """Helper for getting the current status as defined in the redis job details."""
        status_string = self.queue.get_job(self.current_job_id)['status']
        return StatusEnum(status_string)

    @status.setter
    def status(self, status: StatusEnum):
        """Helper for setting the current status in the redis job details."""
        self.queue.update_job_value(self.current_job_id, 'status', status.value)

    @property
    def job_details(self) -> dict:
        """Return current job's hash-map from redis."""
        job_details = self.queue.get_job(self.current_job_id)
        return job_details
