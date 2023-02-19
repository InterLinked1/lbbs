
/* Create user first, if necessary */
/* Uncomment the below if you need to create the BBS user (and change the password!!!) */

--CREATE USER 'bbs'@'localhost' IDENTIFIED BY 'P@ssw0rdUShouldChAngE!';

/* BBS database */

CREATE DATABASE `bbs`;
USE `bbs`;

CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(512) NOT NULL,
  `password` varchar(512) NOT NULL,
  `date_registered` datetime NOT NULL DEFAULT current_timestamp(),
  `last_login` datetime DEFAULT NULL,
  `priv` int(11) NOT NULL DEFAULT 1,
  `name` varchar(512) NOT NULL,
  `email` varchar(512) NOT NULL,
  `phone` varchar(512) DEFAULT NULL,
  `address` varchar(512) DEFAULT NULL,
  `city` varchar(512) NOT NULL,
  `state` varchar(512) NOT NULL,
  `zip` varchar(9) DEFAULT NULL,
  `dob` date DEFAULT NULL,
  `gender` char(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

GRANT ALL PRIVILEGES ON bbs.* TO 'bbs'@'localhost';


/* IRC database */

CREATE DATABASE `irc`;
USE `irc`;

CREATE TABLE `channels` (
  `name` varchar(64) NOT NULL,
  `founder` varchar(64) NOT NULL,
  `topic` varchar(390) DEFAULT NULL,
  `entrymsg` varchar(256) DEFAULT NULL,
  `modelock` varchar(64) DEFAULT NULL,
  `registered` datetime NOT NULL DEFAULT current_timestamp(),
  `guard` tinyint(1) NOT NULL DEFAULT 0,
  `keeptopic` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `channel_flags` (
  `channel` varchar(64) NOT NULL,
  `nickname` varchar(512) NOT NULL,
  `flag` char(1) NOT NULL,
  PRIMARY KEY (`channel`,`nickname`,`flag`),
  CONSTRAINT `channel_flags_ibfk_1` FOREIGN KEY (`channel`) REFERENCES `channels` (`name`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

GRANT ALL PRIVILEGES ON irc.* TO 'bbs'@'localhost';

/* Flush privileges */

FLUSH PRIVILEGES;
