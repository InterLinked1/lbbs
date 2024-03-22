#!/bin/sh

# Helper script to install Docker, extract a Debian filesystem from the container, and generate an archive that can unzipped for a rootfs
# must be run as root (or sudo)
# Helpful resources: https://github.com/sharadg/containers_basics ; https://stackoverflow.com/questions/30379381/docker-command-not-found-even-though-installed-with-apt-get

# Install Docker
curl -sSL https://get.docker.com/ | sh

# Install a Debian 12 container (modify according to your desired guest/host OS)
# Execute commands to install any programs you want available in the container
docker run -it debian:12 apt-get update -y && apt-get install -y less ed vi nano top

# List containers
docker ps -a

# Export the container root filesystem
containerid=`docker ps -a | grep "debian" | xargs | awk '{print $1;}'`
docker export $containerid > rootfs.tar

ls -la rootfs.tar
mkdir rootfs
tar xvf rootfs.tar -C ./rootfs

# Remove the tarball export, no longer needed
# If you want to keep this around for easily recreating
# the rootfs (e.g. at boot up, to have a clean start),
# you may want to keep this around instead
rm rootfs.tar

# Remove artifact of using Docker to create the container
rm ./rootfs/.dockerenv

# Replace username prompt, as described in system.conf
# We use \u as a backup for the sysop manually using isoroot
# to administer the container, since $BBS_USER is only defined within the BBS.
sed -i 's/\\u/${BBS_USER:-\\u}/' ./rootfs/etc/bash.bashrc
