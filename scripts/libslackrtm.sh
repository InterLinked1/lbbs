#!/bin/sh

set -e
cd /usr/local/src
if [ ! -d slack-rtm ]; then
	git clone https://github.com/InterLinked1/slack-rtm.git
	cd slack-rtm
else
	cd slack-rtm
	git stash
	git pull
fi
make
make install
