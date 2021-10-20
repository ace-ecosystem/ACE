# HTML/URL Render Service

The HTML/URL Render service is a suite of containers that function to securely render HTML and URL observables into images. The design of the system is such that, depending on deployment, even malicious content can be rendered. Once rendered, the images can be served through ACE's GUI to analysts, to allow for quick triaging.

## Docker

Several containers are used in orchestration:

- **NGinx Proxy** (`nginx:alpine`): This container is a reverse proxy that achieves two goals:
    - Certificate based client authentication between ACE and the service
    - Reverse proxying HTTP requests to (potentially) multiple **Controllers**
- **Controller** (`tiangolo/uvicorn-gunicorn-fastapi`): This container is a RESTful HTTP API, written in [FastAPI]() that essentially transforms HTTP requests from the primary ACE instance (running the [Render Analyzer module]() into rendering jobs. Multiple of these containers *can* be deployed.
- **Redis** (`redis:latest`): This container functions both as a queue (through a Redis List) for jobs, and as a data store, between the **Controller** and **Renderer**.
- **Renderer** (`selenium/standalone-chrome`): This container does the work of taking a rendering job off the queue and generating the image. The renderer can also use an outbound proxy. The renderer dies after completing or failing to render, and relies of replication for subsequent jobs to be renderered (a major design constraint).

## How the Containers Interact

![Renderer Service Orchestration](../../assets/images/renderer_high_level_diagram.png)

// TODO: update this image to lose AWS specific descriptions
The above image describes how the containers interact.

## Renderer Lifecycle

![Renderer Container Workflow](../../assets/images/renderer_cycle.png)

The **Renderer** container uses selenium's remote webdriver and headless Chrome to generate an image.