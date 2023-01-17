#!/bin/php
<?php
/* Sample IRC bot script for LBBS door_irc module
 * (C) 2023, Naveen Albert
 */

if ($argc < 5) {
	fprintf(STDERR, "Invalid number of arguments: %d\n", $argc);
	/* php doesn't have errno, manually use the appropriate code: https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md */
	exit(22); /* EINVAL */
}

/* $argv[0] is this script's name */
$fromIRC = ((int) $argv[1]) == 0 ? false : true;
$channel = $argv[2];
$sender = $argv[3];
$message = $argv[4];

/* If somebody messages us directly, the channel is our own username.
 * This script doesn't actually know what that is, but if channel
 * doesn't start with # or &, then it's a private message. */
$prefix = ((substr($channel, 0, 1) === "#" || substr($channel, 0, 1) === "&") ? $channel : $sender) . " ";

/* This must be initialized here, before it's used. */
$handlers = array(
	'help' => array('help [<command>]. Shows command help.', 'handler_help'),
	'echo' => array('echo [<args>]. Echoes input text back to the sender', 'handler_echo'),
);

if (substr($message, 0, 1) === "!") {
	/* ! IRC bot command */
	$message = substr($message, 1);
	$command = strtok($message, ' '); /* First word */
	if ($command === false) {
		$command = $message; /* There is nothing after the command */
	} else {
		/* strtok in PHP does not advance the message, like strsep in C does
		 * There might be a better way to do this, but I'm so much more used
		 * to C programming that PHP is oddly complicated for me now :) */
		 $message = substr($message, strlen($command) + 1);
	}
	if (!array_key_exists($command, $handlers)) {
		echo $prefix . "Sorry, I don't understand that command.";
	} else {
		$handler = $handlers[$command];
		call_user_func($handler[1], $prefix, $fromIRC, $channel, $sender, $message);
	}
/* Can do stuff based on the channel, message contents, sender, etc... */
} else if ($message === "See you later, alligator" || $message === "See you later alligator") { /* could use str_starts_with in PHP 8+ */
	echo $prefix . "After a while, crocodile";
} else {
	exit(38); /* ENOSYS */
}
/* Implicit exit(0) */

/* == IRC bot command handlers == */

function handler_help(String $prefix, bool $fromIRC, String $channel, String $sender, String $message) {
	global $handlers;
	$command = strtok($message, ' '); /* Next word */
	if ($command === false) {
		/* No word following. Show all commands. */
		$commandNames = array_keys($handlers);
		echo $prefix . implode(' | ', $commandNames);
	} else if (!array_key_exists($command, $handlers)) {
		echo $prefix . "Sorry, I can't help you.";
	} else {
		$handler = $handlers[$command];
		$helptext = $handler[0];
		echo $prefix . $helptext;
	}
}

function handler_echo(String $prefix, bool $fromIRC, String $channel, String $sender, String $message) {
	echo $prefix . $message; /* Echo remainder */
}

?>