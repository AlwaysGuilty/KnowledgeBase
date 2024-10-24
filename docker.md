# Docker

Run a Dockerized app locally:
* Build image: `docker compose build`
* Start container with `docker compose up`
* You can also do both at the same time with `docker compose up --build -d`.
* Stop the app with `Ctrl-C` and run:
  * `docker compose down` and
  * `docker image prune -a -f`

Some helpful Docker commands:
| Command | Description |
|-|-|
| `docker ps` | list running containers |
| `docker ps -a` | list ALL containers |
| `docker images` | list images |
| `docker rmi -f <image id>` | force remove image |
| `docker rm <container>` | remove container |
| `docker container prune -f` | force remove all stopped containers |
| `docker image prune` | remove dangling images |
| `docker image prune -a -f` | force remove all unused images |
| `docker compose start` | start existing container/s |
| `docker compose down` | stop and remove container/s and networks |
| `docker build -t <image name> .` | build an image directly from a Dockerfile from current directory |
| `docker run --name <friendly name> -d -p <internal port>:<external port> <image name>` | start a container with a friendly name from image in detached mode |
| `docker exec -it <container id> /bin/bash` | execute `/bin/bash` in a given container -> it connects you to the container |
| `docker run --name <friendly name> -it <image name> /bin/bash`| run the container and execute shell |
| `docker save -o /path/to/file.tar <image name>` | Save docker image to a tar file. Useful for A/D pwns without source. |
| `docker load -i /path/to/file.tar` | Load image from a file. |

Tips:
- `.dockerignore` - a file that works in the same fashion as `.gitignore`
- Specify image version like this: `FROM ubuntu:18.04@sha256:8da4e9509bfe5e09df6502e7a8e93c63e4d0d9dbaa9f92d7d767f96d6c20a78a`
- Make container noninteractive: `ENV DEBIAN_FRONTEND=noninteractive` - no interaction needed for installing some packages
