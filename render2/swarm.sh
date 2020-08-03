#!/usr/bin/env bash

set -e

#--------------------------------------------------------------------
# Variables
#--------------------------------------------------------------------

USAGE="./swarm.sh [start|stop] [force]"

STARTMSG="[RENDER_SWARM]"
STACK_NAME="render"
RENDER_IMAGE="render:latest"
CONTROLLER_IMAGE="controller:latest"
NGINX_IMAGE="render_nginx:latest"

RENDERER_BUILT="false"
CONTROLLER_BUILT="false"
NGINX_BUILT="false"

#--------------------------------------------------------------------
# Functions
#--------------------------------------------------------------------

function build_render() {
  echo "$STARTMSG building Docker image render:latest"
  docker build -t render:latest -f src/renderer/Dockerfile src/shared/
  RENDERER_BUILT="true"
}

function build_controller() {
  echo "$STARTMSG building Docker image controller:latest"
  docker build -t controller:latest -f src/controller/Dockerfile src/shared
  CONTROLLER_BUILT="true"
}

function build_nginx() {
  echo "$STARTMSG building Docker image render_nginx:latest"
  docker build -t render_nginx:latest src/nginx
  NGINX_BUILT="true"
}

function start_service() {
  echo "$STARTMSG starting stack name $STACK_NAME"
  docker stack deploy -c swarm-stack.yml $STACK_NAME
}

function stop_service() {
  echo "$STARTMSG stopping stack name $STACK_NAME"
  docker stack rm $STACK_NAME
}

function force_build_if_required() {
  # Note $1 here is $2 in main
  case "$1" in
  force)
    echo "$STARTMSG forcing rebuild of Docker image render:latest"
    build_render
    echo "$STARTMSG forcing rebuild of Docker image controller:latest"
    build_controller
    echo "$STARTMSG forcing rebuild of Docker image render_nginx:latest"
    ;;
  *)
    echo "$STARTMSG will not force rebuild"
    ;;
  esac
}


#--------------------------------------------------------------------
# Handle image dependencies for swarm
#--------------------------------------------------------------------

# Check to see if docker engine is in swarm mode
if [[ "$(docker info | grep Swarm)" == *"inactive"* ]]; then
  echo "Docker Swarm is not initialized. Run the following command and try again:"
  echo " --> 'docker swarm init'"
  exit 1
fi

# Input validation before building dependencies
case "$1" in
start|stop)
  ;;
*)
  echo "Usage: ${USAGE}"
  exit 1
  ;;
esac

docker images | egrep '^render\s+latest' || build_render
docker images | egrep '^controller\s+latest' || build_controller
docker images | egrep '^render_nginx\s+latest' || build_nginx

# If image was not just built, check to see if we should force rebuild
# TODO - WE NEED TO MAKE THIS MORE GRANULAR PER CONTAINER
if [[ "$RENDERER_BUILT" != "true" && "$CONTROLLER_BUILT" != "true" && "$NGINX_BUILT" != "true" ]]; then
  echo "$STARTMSG checking if we should force rebuild the renderer"
  force_build_if_required $2
fi

#--------------------------------------------------------------------
# Swarm/service management
#--------------------------------------------------------------------
case "$1" in
start)
  start_service
  echo "View logs:                'docker service logs [${STACK_NAME}_redis|${STACK_NAME}_render|${STACK_NAME}_controller|${STACK_NAME}_nginx]'"
  echo "View running services:    'docker stack ps $STACK_NAME'"
  ;;
stop)
  stop_service
  echo "If developing locally, and you are a single swarm node, you can turn swarm mode off by running:"
  echo " --> 'docker swarm leave --force'"
  ;;
esac
