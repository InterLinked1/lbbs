#!/bin/sh
# NOTE: This script should be run from the current (scripts) directory
apt-get install -y cppcheck
cppcheck .. --std=c99 -I ../include -I ../tests -f --enable=all --error-exitcode=1 -UTEST_MODULE_INFO_STANDARD -UTEST_MODULE_SELF_SYM --suppressions-list=.suppress.cppcheck
