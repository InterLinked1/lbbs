#!/bin/sh

# Disable broadcast wall messages from syslog to avoid interfering with terminal sessions
# Won't affect BBS nodes either way, but could be annoying to the sysop if not done
# Recommended if syslog is enabled on this server

# Test before
logger -p local0.emerg "This is a test, not a real emergency"

# Disable default emergency rule: *.emerg :omusrmsg:*
sed -e '/*.emerg/ s/^#*/#/' -i /etc/rsyslog.conf

# Disable forwarding to wall for journald
sed -i 's/#ForwardToWall=yes/ForwardToWall=no/' /etc/systemd/journald.conf

# Reload
systemctl force-reload systemd-journald
systemctl restart rsyslog

# Test again: this should no longer generate a broadcast
logger -p local0.emerg "This is a test, not a real emergency"
