
import uuid

from fastapi import FastAPI, Form, Query, Response, status, HTTPException, Depends
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel

from enums import StatusEnum, OutputTypeEnum, ContentTypeEnum
from job_queue import JobQueue
from shared_logging import get_logger, prep_for_logging

logger = get_logger(__name__)

app = FastAPI()
job_queue = JobQueue()


class Queue():
    """A wrapper around an instance of JobQueue to allow for dependency injection"""
    def __init__(self):
        self.q = job_queue


# Models
class JobIn(BaseModel):
    content_type: ContentTypeEnum
    content: str
    output_type: OutputTypeEnum
    output_name: str = None
    width: int
    height: int


class JobOut(BaseModel):
    id: uuid.UUID = None
    content_type: ContentTypeEnum
    content: str
    output_type: OutputTypeEnum
    output_name: str = None
    width: int
    height: int
    status: StatusEnum
    data: bytes = None


# Routes
@app.get("/ping", status_code=status.HTTP_200_OK)
@app.get("/ping/", status_code=status.HTTP_200_OK)
def heartbeat():
    return

# TODO: Starlette automatically strips trailing slashes on routes and redirects
#       to a matched route. The redirect does not properly include proxy information
#       (host, port, etc), so the subsequent request, if followed, will fail. We will
#       need to implement a uvicorn middleware to properly handle redirects. See: 
#       https://github.com/encode/uvicorn/blob/master/uvicorn/middleware/proxy_headers.py


@app.post("/job", status_code=status.HTTP_201_CREATED, response_model=JobOut)
@app.post("/job/", status_code=status.HTTP_201_CREATED, response_model=JobOut)
def create_job(job: JobIn, queue: Queue = Depends()):
    # generate UUID
    id = uuid.uuid5(uuid.NAMESPACE_DNS, job.content)
    id_string = str(id)
    
    already_id = queue.q.get_job(id_string)
    # check if id already exists
    if already_id is not None:
        logger.error(f'unable to create new job. job "{id_string}" already exists.')
        raise HTTPException(status_code=status.HTTP_409_CONFLICT)

    # convert to dictionary
    try:
        json_job = jsonable_encoder(job)
    except Exception as e:
        _job_for_logging = prep_for_logging(job.dict())
        logger.error(f'unable to serialize job to json: "{_job_for_logging}". {e.__class__}, {e}')


    # update attributes
    json_job["id"] = id_string
    json_job["status"] = "queued"

    # create job in redis
    queue.q.add_job(json_job)
    
    # convert to model
    try:
        return_job = JobOut(**json_job)
    except Exception as e:
        logger.error(
            f'unable to convert json to Job: "{prep_for_logging(json_job)}". {e.__class__}, {e} - '
            f'returning an HTTP 500'
        )
        # If we don't have a return job, then we can't return it. So raise a 500 error.
        # Redis key expiry set in 'queue.q.add_job()` will make sure the job gets garbage collected
        # within redis.
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    # return JSON
    logger.info(f'created new job: {prep_for_logging(return_job.dict())}')
    return return_job


@app.get("/job/{job_id}", status_code=status.HTTP_202_ACCEPTED, response_model=JobOut)
def get_job(job_id: str, queue: Queue = Depends()):
    # query redis for job
    job_dict = queue.q.get_job(job_id)
    if job_dict is None:
        logger.error(f'unable to find job: "{job_id}"')
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    
    # convert to model
    try:
        job = JobOut(**job_dict)
    except Exception as e:
        logger.error(
            f'unable to convert dict to Job: "{prep_for_logging(job_dict)}". {e.__class__}, {e} - '
            f'raising an HTTP 500 error'
        )
        # If we can't convert to the JobOut object, then we have nothing to return
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    logger.info(f'returning job "{job_id}": {prep_for_logging(job.dict())}')
    return job


@app.delete("/job/{job_id}", status_code=status.HTTP_200_OK)
def delete_job(job_id: str, queue: Queue = Depends()):
    job_dict = queue.q.get_job(job_id)
    
    if job_dict is not None:
        queue.q.remove_job(job_id)
        logger.info(f'deleted job "{job_id}": {prep_for_logging(job_dict)}')
    else:
        logger.info(f'job "{job_id}" was not found and could not be deleted')

    # always return 200, even if job did not exist
    return Response(status_code=status.HTTP_200_OK)
