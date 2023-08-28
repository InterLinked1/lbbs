#!/bin/sh

# WARNING: DO NOT USE THIS SCRIPT. It is not currently suitable for use.

# This is a helper script meant to highlight
# formatting inconsistencies in the codebase.
#
# For example, Notepad++ has a bug where when a file
# is opened or focused, it will change the tab alignment
# of the currently selected line. If the programmer does
# not catch this, this will introduce erroneous malformatting.
#
# The actual result of running this script should
# not be directly commited. The results should be
# analyzed manually, with changes made as needed
# (git diff, followed by git stash)

if ! which "indent" > /dev/null; then
	apt-get install -y indent
fi

if [ ! -d .git ]; then
	printf "Must be run inside a Git repository\n"
	exit 1
fi

# All the options are specified here
export INDENT_PROFILE=scripts/.indent.pro

# We're inside a Git repo and just do "git stash", don't make backup copies
export VERSION_CONTROL=never

# indent seems to be buggy, in that
# --dont-format-comments seems to have no effect,
# and comments are STILL modified. Thus, most of
# the diff from indent is unwanted and superflous,
# and must be ignored.

# git diff is not capable of matching only certain changes in the staging area.
# We could use some fancy post-processing to do this, though this is hard.
# grepdiff (part of patchutils) does not support negative matches, which are needed to exclude comments.

indent -nfca bbs/*.c doors/*.c modules/*.c nets/*.c nets/net_imap/*.c tests/*.c
git stash
