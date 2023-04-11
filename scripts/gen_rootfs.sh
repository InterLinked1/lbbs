#!/bin/sh

# Helper script to install Docker, extract a Debian filesystem from the container, and generate an archive that can unzipped for a rootfs
# must be run as root (or sudo)
# Helpful resources: https://github.com/sharadg/containers_basics ; https://stackoverflow.com/questions/30379381/docker-command-not-found-even-though-installed-with-apt-get

# Install Docker
curl -sSL https://get.docker.com/ | sh

# Install a Debian 11 container (modify according to your desired guest/host OS)
# Execute commands to install any programs you want available in the container
docker run -it debian:11 apt-get update -y && apt-get install less nano

# List containers
docker ps -a

# Export the container root filesystem
containerid=`docker ps -a | grep "debian" | xargs | awk '{print $1;}'`
docker export $containerid > rootfs.tar

ls -la rootfs.tar
mkdir rootfs
tar xvf rootfs.tar -C ./rootfs
