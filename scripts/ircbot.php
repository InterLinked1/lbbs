#!/usr/bin/php
<?php
/* Sample IRC bot script for LBBS door_irc module
 * (C) 2023, Naveen Albert
 */

if ($argc !== 5) {
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
	'hello' => array('hello. Says hello', 'handler_hello'),
	'time' => array('time. Provides current time.', 'handler_time'),
	'define' => array('define <word>. Defines a word.', 'handler_define'),
	'fprnow' => array('fprnow. Currently playing song on Flower Power Radio', 'handler_fprnow'),
	'fprrecent' => array('fprrecent. Lists 4 most recently played songs on Flower Power Radio', 'handler_fprrecent'),
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
		fprintf(STDERR, "Unknown command: %s\n", $command);
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

function handler_hello(String $prefix, bool $fromIRC, String $channel, String $sender, String $message) {
	echo $prefix . "Hello world!";
}

function handler_time(String $prefix, bool $fromIRC, String $channel, String $sender, String $message) {
	echo $prefix . date("l F d, h:i:s A", time());
}

function handler_define(String $prefix, bool $fromIRC, String $channel, String $sender, String $message) {
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, "dict://dict.org/define:($message):english:exact");
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	$definition = curl_exec($ch);
	curl_close($ch);

	/* Skip to the first definition. */
	$definition = strstr($definition, " 1. ");
	$definition = substr($definition, 4); /* Skip " 1. " */

	/* Strip out any remaining protocol headers and metadata */
	$s = "";
	$response = explode("\r\n", $definition);
	foreach($response as $r) {
		$first = strtok($r, ' ');
		if (strlen($first) === 3 && ((int) $first) > 0) {
			continue;
		}
		$s .= $r . " "; /* Put everything on a single line */
	}

	echo $prefix . $s; /* XXX Could be truncated if longer than 512 chars */
}

/* Currently playing song on Flower Power Radio */
function handler_fprnow(String $prefix, bool $fromIRC, String $channel, String $sender, String $message) {
	echo $prefix . " " . file_get_contents("http://nl1.streamingpulse.com:7016/currentsong");
}

function handler_fprrecent(String $prefix, bool $fromIRC, String $channel, String $sender, String $message) {
	/* Requires php-dom extension: apt-get install php-dom */
	$html = file_get_contents("https://widgets.autopo.st/widgets/public/Steve7/recentlyplayed.php");
	$dom = new DOMDocument();
	error_reporting(E_ERROR); /* Don't emit warnings for malformed XML */
	$dom->loadHtml($html);
	$x = new DOMXpath($dom);
	$c = 0;
	foreach($x->query('//td') as $td) {
		$x = trim($td->textContent);
		if ($x !== "") {
			if ($c === 0) {
				echo $prefix;
			} else {
				echo " || "; /* Double up to prevent text formatting inbetween */
			}
			echo ++$c . ". " . trim($td->textContent);
		}
	}
	if ($c === 0) {
		fprintf(STDERR, "Failed to parse song names from response\n");
	}
}
?>