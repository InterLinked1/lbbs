#!/bin/sh

# Helper script to install Docker, extract a Debian filesystem from the container, and generate an archive that can unzipped for a rootfs
# must be run as root (or sudo)
# Helpful resources: https://github.com/sharadg/containers_basics ; https://stackoverflow.com/questions/30379381/docker-command-not-found-even-though-installed-with-apt-get

# WARNING: This script installs Docker temporarily to create the filesystem, which can be detrimental to your system.
# Although the script attempts to remove Docker after running and clean up the system, artifacts from the Docker installation may linger.
# It is recommended to run this script on a development or throwaway system, to avoid causing issues to a production system.

apt-get install -y curl

# Install Docker
curl -sSL https://get.docker.com/ | sh

# Install a Debian 12 container (modify according to your desired guest/host OS)
# Execute commands to install any programs you want available in the container
# libncurses6 is needed for running external/filemgr (copied at the bottom of this script)
#
# You can also install software later as needed in the container template.
# Use the -n option to keep network connectivity inside the container (needed for apt-get)
docker run -it debian:12 apt-get update -y && apt-get install -y less ed vi nano top libncurses6 lrzsz

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

# Disable the apt sandbox so we can run apt-get update using external/isoroot -n:
# Adapted from 2nd answer here: https://stackoverflow.com/a/71096036/
if [ -f /rootfs/etc/apt/apt.conf.d/sandbox-disable ]; then
	sed -i 's/_apt/root/' ./rootfs/etc/apt/apt.conf.d/sandbox-disable
else
	printf "Couldn't find file in container filesystem: %s\n" "/etc/apt/apt.conf.d/sandbox-disable"
	printf "apt-get update will not work inside the container!\n"
fi

# Copy added terminfo definitions from /etc/terminfo
cp -r /etc/terminfo/* ./rootfs/etc/terminfo

# Add binaries that are useful inside the BBS
cp /var/lib/lbbs/external/filemgr ./rootfs/bin

# Stop Docker and clean up. We only needed it to conveniently create the container file system for us, the BBS itself doesn't use it while running.
service docker stop
systemctl disable docker.service
systemctl disable docker.socket

apt-get purge -y docker-engine docker docker.io docker-ce docker-ce-cli docker-compose-plugin docker-buildx-plugin docker-ce-rootless-extras # Remove all the docker junk
dpkg -l | grep -i docker # Hopefully it's all gone?

# Docker installs a bunch of iptable rules that will break the system. For exmaple, it changes FORWARD to DROP by default rather than ALLOW.
# Even after uninstalling, this rules persist (ugh, why?), which can cause problems with other programs.
# Assuming this is a new system, it should be safe to clear out all the rules to start fresh.
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X

# Do not attempt to copy the rootfs directly between systems
# To move the rootfs to another system
# On the source system: tar -cvf rootfs.tar ./rootfs
# Copy rootfs.tar to the target system
# On the target system run: tar -xvf rootfs.tar
# Then run: chown -R root:root /var/lib/lbbs/rootfs/
# Then run: /var/lib/lbbs/external/isoroot -n /var/lib/lbbs/ (not /var/lib/lbbs/rootfs as you might think!)
# Inside the container, run: echo 'APT::Sandbox::User "root";' > /etc/apt/apt.conf.d/sandbox-disable
# Inside the container, run: echo -e "nameserver 1.1.1.1" > /etc/resolv.conf
# Now, you can install any programs that may be needed for users inside their containers
# e.g.:
# apt-get install nano
#   (Note that running nano in the container will error:
#     Unable to create directory /root/.local/share/nano/: Permission denied
#     It is required for saving/loading search history or cursor positions.
#   This is because nano ignores $HOME if the username is root; nano still works for the most part though.
#   /etc is symlinked to the rootfs template, so we can't just modify the home dir of root in /etc/shadow
