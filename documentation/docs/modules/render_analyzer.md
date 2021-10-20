# HTML/URL Renderer

This module allows for render/screenshot of URL and file observables.

The analyzer is used in conjuction with the `BaseRenderClient` found in `saq.render`, which is responsible for handling requests for render job creation, watching, and output download.

Currently only `RenderControllerClient` has been created, which is desgined to be used with the Controller/Redis/Render model, in which HTTP requests are used for communication with the controller service.

In the future, and Render client designed to interact directly with Redis (or other queue) may be considered.

## Analysis

The Render Analyzer accepts both file and URL observables and performs the following actions.

- Verifies required configuration exists
- Loads observable content and configuration to submit render request
    - URL content loaded is just the URL
    - HTML content loaded is the file contents using the filename
        - if HTML, the module also checks prior `FileTypeAnalysis` in order to ensure the file is indeed an HTML file
- Submits work item with request contnet
- 'Watches' work item until it moves from 'queued' to 'in_progress' to 'complete'
  - Chance for a timeout at this point; if that happens, the analysis is delayed.
    - If a timeout occurs during *delayed* analysis the analysis will fail (in order to prevent recursion)
  - If the work item has status 'failed', the analysis will fail
- Upon completion, gets output data of work item
- Writes the output data to a file within alert's root directory with name `renderer_{observable_id}.png`
    - `RenderControllerClient` output data: an encoded string stored in Redis. Saved by writing decoded data to file.
- Screenshot file is added to alert as an observable with `DIRECTIVE_EXCLUDE_ALL`, as there is no analysis to be done for the screenshot

## Configuration

```ini
[analysis_module_render]
module = saq.modules.render
class = RenderAnalyzer
enabled = no

; determines what client to use, RenderControllerClient currently only existing implementation
; ex. in the future add RenderRedisClient to connect directly to Redis instance
session_type = controller

base_uri =
port =
verify =
client_cert =
auth_token =

output_type = redis
output_width = 1024
output_height = 1024

; how long to sleep between checking for job completion (seconds)
watch_sleep_time = 20
; how long to wait for job completion before raising timeout (seconds)
watch_timeout_time = 300
```

If using Docker Swarm for local Renderer service, your `base_uri` can be easily found with comamand `docker node ls` using the HOSTNAME value for the node your Swarm is running on.

## Adding a New Render Client

If you would like to create a new client for use with this module, there are a few places that changes will be required:

- New Client class in `saq.render` derived from `BaseRenderClient` that implements all abstract methods, `submit_work_item`, `watch`, `renderer_finished`, and `get_output_data`
- `RENDER_SETUP_MAP` in `saq.modules.render` should be updated to included `key:value` pair equivalent to `analysis_module_render.session_type`:`RenderClientClassName` 
- Update config to include any appropriate connection variables, and set the `session_type` to the new value you defined in `RENDER_SETUP_MAP`
