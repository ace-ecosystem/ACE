# HTML/URL Render Service

The HTML/URL Render Service is a suite of containers that function to securely render HTML and URL `Observables` into images. The design of the system is such that, depending on deployment, even malicious content can be rendered. Once rendered, the images can be served through ACE's GUI to analysts, to allow for quick triaging.

## Local Development

The suite of containers are orchestrated through either **Docker Compose** or **Docker Swarm**. Running the suite through Swarm will allow for auto replication of expired **Renderer** containers, at the expense of a single log file. You can run the service through either of these, but understand that with `docker-compose`, only a single render job will be processed.

## Docker

Docker is configured to use the `render2/src/shared` folder as the build context. Dockerfiles can be found at:

- `render2/src/controller/Dockerfile`
- `render2/src/nginx/Dockerfile`
- `render2/src/renderer/Dockerfile`

The containers that are deployed are based on the following DockerHub images:

- nginx: `nginx:alpine`
- controller: `tiangolo/uvicorn-gunicorn-fastapi`
- redis: `redis:latest`
- renderer: `selenium/standalone-chrome`

## Docker Compose

The `docker-compose.yml` file is at `render2/`. To run the containers locally through `docker-compose`, follow these steps:

1. `cd render2`
1. `docker-compose build`
1. `docker-compose up`

## Swarm

The `swarm-stack.yml` file is at `render2/`. To run the containers locally through swarm, use the `render2/swarm.sh` script, and follow these steps:

1. `cd render2`
1. `./swarm.sh start`

You can force swarm to rebuild all the container images through `./swarm.sh start force`

## Pytest

**Tests must be run from the root ace directory!** All tests related to the renderer are in `tests/render2`. Tests span both `unit` and `integration`. Tests marked `integration` will spin up containers through Docker, so you will need to ensure that you are not running any containers locally that would conflict. Integration tests also have a longer runtime, due to container start/stop time (and potentially build time).

If you want the renderer to use a web proxy while running tests:
1. Run `cd /path/to/ice && cp /path/to/ice/.env.template /path/to/ice/.env`
2. Fill in the variables. DO NOT commit the `.env` file to version control.

## Reverse Proxy

The nginx proxy serves two functions:

1. It terminates the HTTPS client-based certificate authentication.
2. It reverse proxies requests to (potentially) multiple **Controller** containers running.

You can pass a Base64 encoded string of the certificates as environment variables to dynamically set the
server certificates as well as the CA for the client certificates:
- `NGINX_SERVER_NAME` - The host as seen from the client's perspective
- `NGINX_X509_PRIVATE_KEY_B64` - Base64 encoded string of the private x509 server key
- `NGINX_X509_PUBLIC_CERT_B64` - Base64 encoded string of the public x509 server cert
- `CLIENT_CERT_CA` - Base64 encoded x509 public certificate that signed the client certificates (used for auth)
- `UVICORN_HOST` - Hostname/ip of the Controller container
- `UVICORN_PORT` - Port the Controller is listening on

These values will be dynamically injected into the `nginx.conf` file at container
startup.

Nginx container listens on port 8443 by default

There is a helper script to generate your own server x509 certs, CA, and client-signed certs.

1. Make sure you have openssl installed
2. `cd /path/to/ice/render2/src/nginx`
3. `./gen_test_certs.sh`

## Controller

The **Controller** is implemented as a [FastAPI](https://fastapi.tiangolo.com/) HTTP API. It uses several [`pydantic`](https://pydantic-docs.helpmanual.io/) models to perform validation on requests & data:
- `JobIn`
- `JobOut`

It has the following endpoints:

| Endpoint     | HTTP    | Request Body | Response Body | codes |
| ------------ | ------- | ----------- | ----------- | --- |
| `job/`         | POST    | `{`<br>`  "content_type": "url",`<br>`  "content": "https://www.google.com" `<br>`  "output_type": "redis",`<br>`  "width": 1024,`<br>`  "height": 1024`<br>`}` | `{`<br>`  "id": "b5530f79-9084-394d-b8d0-8e1ec8c77dc5",`<br>`  "content_type": "url",`<br>`  "content": "https://www.google.com",`<br>`  "output_type": "redis",`<br>`  "width": 0,`<br>`  "height": 0`,<br>`  "status": "queued",`<br>`  "data": null`<br>`}` | `201`, `409`, `422`, `500` |
| `job/{job_id}` | GET     |     | `{`<br>`  "id": "b5530f79-9084-394d-b8d0-8e1ec8c77dc5",`<br>`  "content_type": "url",`<br>`  "content": "https://www.google.com",`<br>`  "output_type": "redis",`<br>`  "width": 0,`<br>`  "height": 0`,<br>`  "status": "processing",`<br>`  "data": "base64string`<br>`}` | `404`, `500` |
| `ping/`        | GET     |     |    | `200` |


Controller container can be populated with environment variables:
- `REDIS_HOST` - Hostname or IP of the redis database
- `REDIS_PORT` - Port to use for Redis
- `REDIS_DB`   - Database to use on the Redis host. **NOTE** this needs to be the
same for the controller and renderer containers.
- `JOB_QUEUE_KEY` - The name of the job queue. **NOTE** should be set to the same
value for the controller and renderer.
- `PORT` - The port the controller should listen on. **NOTE** should be set to the same value for
the `UVICORN_PORT` on the nginx container. Port `8080` is preferred.


### Documentation

Once the controller is deployed, it automatically provisions [interactive API documentation](https://fastapi.tiangolo.com/#interactive-api-docs) at the following endpoints:

- `{root_url}/docs` through [Swagger](https://swagger.io/)
- `{root_url}/redoc` through [Redoc](https://redoc.ly/docs)

### Postman

A full suite of Postman requests and tests are included. Due to client-based cert authentication, you will need to [configure Postman to use client certificates](https://learning.postman.com/docs/sending-requests/certificates/) before sending requests. **If cert-based authorization is not configured, no requests will be served!**

You can import the test suite through Postman using the `tests/render2/RenderTests.postman_collection.json`. Within the Collection are several folders:

- **Happy Path URL**    - this suite replicates the [ACE Render Analysis Module's](../modules/render_analyzer.md) behavior for a job containing just a URL:
    - POST a new job.
    - GET the newly created job until job status resolves.
- **Happy Path HTML**   - this suite replicates the [ACE Render Analysis Module's](../modules/render_analyzer.md) behavior for a job containing pre-crawled HTML, similar to the above.
- **Sad Path**          - this suite tests all of the controller's data validation for incorrect values
- **Misc**              - this suite contains miscellaneous requests, such as the `/ping` heartbeat and redirect behavior.

## Redis

Redis is configured to communicate with both the **Controller** and the **Renderer**. Redis controls the lifetime of jobs (completed or not) through it's expiry settings.

### Configuration

Redis currently uses the following parameters:

- Port: 6379
- DB: 0

### Redis Schema

The redis schema uses the following keys:

- `render:queue:incoming`: stores a `Redis.List` of all new `job_id`s that are waiting to be processed
- `render:job:<job_id>`: stores each job's hashmap


#### Job Hashmap

A job in redis is represented as follows:

``` 
{
    "id": "string"              - Value is the job id
    "content": "string"         - Value should be the URL or the HTML string
    "content_type": "string"    - Value should be 'url' or 'html'
    "output_type": "string"     - Value should be 'file' or 'redis'
    "output_name": "string"     - Value should be file path + file name like /path/to/screenshot.png or redis key to store binary at or S3 object path
    "width": integer            - Screenshot width in pixels
    "height": integer           - Screenshot height in pixels
    "status": "string"          - Value should be (queued, in_progress, completed, failed)
}
```

## Renderer

The **Renderer** executes the following steps:

1. Checks for a `job_id` in the queue. If the queue is empty, the renderer `sleep()`s.
1. Takes a job, extracts necessary information and sends it to the remote selenium webdriver.
1. Received the rendered picture data and stores it.

It abstracts away the storage method through the `BaseStorage` class, and subclasses.

See more at [**Renderer** lifecycle](../design/render_service.md#renderer-lifecycle)

Environment variables at runtime:
- `REDIS_HOST` - Hostname or IP of the redis database
- `REDIS_PORT` - Port to use for Redis
- `REDIS_DB`   - Database to use on the Redis host. **NOTE** this needs to be the
same for the controller and renderer containers.
- `JOB_QUEUE_KEY` - The name of the job queue. **NOTE** should be set to the same
value for the controller and renderer.
- `PROXY_HOST` - Hostname of the proxy if applicable. If this environment variable is
not populated, the proxy settings are not set.
- `PROXY_PORT` - Port for the proxy if applicable
- `PROXY_USER` - Username for proxy if applicable (not required to use proxy)
- `PROXY_PASS` - Password for proxy if applicable (not required to use proxy)

### Data Storage

The rendered picture data was designed to be stored in a variety of ways. Currently, data is stored as a `base64` encoded string directly in the Redis [job hashmap](#job-hashmap). This could eventually be extended to file storage or S3 bucket storage.

## Shared code

Some code is shared across containers.

### JobQueue

The `JobQueue` class essentially abstracts away Redis, and allows both the **Controller** and **Renderer** to access jobs through a single API, without needing direct access to Redis.

### CachedJob

The **Renderer** creates a `CachedJob` in its main `run()` loop, which grabs a job off the queue and stores it for the lifetime of the **Renderer**.

### Logging

Each module has it's own logger, and each logger uses a special `TruncatingFormatter` object. This prevents the logged messages from exceeding a maximum size (`MAX_BYTES` in `render2/src/shared/shared_logging.py`).
