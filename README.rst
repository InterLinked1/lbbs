============================================
LBBS - The Lightweight Bulletin Board System
============================================

.. contents:: Contents
.. section-numbering::

Welcome! Whether you're new to BBSing or a veteran sysop, LBBS was written to be a highly configurable, modular BBS for developers, sysops, and users alike.

LBBS is a BBS (bulletin board system) package and personal server written from the ground up to be extensible, modular, and, of course, lightweight.
The codebase is relatively small (~80K SLOC), with relatively few dependencies. It is designed to be easy for sysops to administer, easy for users to use and navigate, and easy for developers to read, understand, maintain, and contribute to the source code.

While LBBS is first and foremost a BBS server, its different components can also be used individually: for example, you could use the mail modules as a private mail server, and not load the BBS-related functionality.

Features
========

Key features and capabilities include:

* Fast and lightweight, written entirely in C

* Terminal access via Telnet, RLogin, SSH, and UNIX domain socket support *(note that Telnet and RLogin are plain text protocols and thus insecure)*

* ANSI art support

* File transfers via FTP, SFTP, Gopher, HTTP/HTTPS, and ZMODEM

* HTTP 1.1 web server, with WebSocket and forward-proxy support

* User home directories

* Container environment for executing programs

* Password and public key authentication

* Config-file driven configuration

* Submenu "skip menu navigation" - select options in multiple nested menus at once
* Automatic menu screen generation and resizing
* Electronic mail (SMTP, POP3, IMAP4)

  * Aliases and subaddressing
  * Mailing lists
  * Mailbox quotas
  * Shared mailboxes and ACL controls
  * Multi-domain support
  * Relay support
  * Advanced queuing support
  * IMAP NOTIFY support
  * RFC 4468 BURL IMAP and server-side proxied append support, for more efficient (bandwidth saving) email submission
  * Remote mailboxes (IMAP proxy)

    * Built-in OAuth2 proxy, allowing the BBS to log in to remote IMAP servers using OAuth2, while your IMAP client uses your normal BBS credentials

  * SPF, DKIM, ARC, DMARC, and SpamAssassin support

  * Filtering

    * Sieve filtering scripts and ManageSieve service
    * `MailScript filtering engine <configs/.rules>`_ for flexible, custom, dynamic mail filtering rules (Sieve alternative)
	* Intelligent sender/recipient analysis - prevent yourself from ever sending an email to the wrong people by mistake!

  * Webmail client backend

* Newsgroups (NNTP)

* Native realtime chat

* Internet Relay Chat client and server (including ChanServ), with native IRC, Slack, and Discord relays

* Queue agent position system for Asterisk

* Terminal autodetection (ANSI support, link speed)

* Emulated slow baud rate support

* TDD/TTY (telecommunications device for the deaf) support

* Sysop capabilities

  * Node spying
  * Interrupt nodes
  * Kick nodes

Usage
=====

Installation
~~~~~~~~~~~~

To install LBBS, you will need to compile it from source. Fortunately, we've made this as easy as possible::

     cd /usr/local/src
     git clone https://github.com/InterLinked1/lbbs.git
     cd lbbs
     ./scripts/install_prereq.sh
     make modcheck
     make modconfig
     make
     make install
     make samples
     make service

(Running :code:`make modcheck` is optional. It will tell you all the modules that are available and which will be disabled for the current build.
Running :code:`make modconfig` is what actually makes changes to the build environment, disabling any modules with unmet dependencies.)

If you are setting up a Linux server from scratch, you may also want to refer to :code:`scripts/server_setup.sh` for a more complete script to set up your BBS server.

Afterwards, you may optionally choose to use :code:`scripts/setup_wizard.sh`, a simple utility to do some basic configuration initialization for you. However, this tool is not comprehensive.

To start the BBS with the sysop console in the foreground, you can then run :code:`lbbs -c`. To daemonize it, just run :code:`lbbs`.

At the console, press :code:`?` or :code:`h` for a list of available commands. You can also run :code:`lbbs -?` or :code:`lbbs -h` for a list of startup options.

Some configuration of the BBS will be needed before you can use it. Consult the sample configs in :code:`/etc/lbbs` for an overview of settings you may need to configure. At a minimum, you will need to add a menu to the BBS (:code:`menus.conf`).

LBBS is best run on a modern version of Debian Linux (Debian 11 or 12). It should also compile on most other commonly used Linux distros. A recent version of gcc is required (e.g. >= 11).
The BBS core should compile and install on FreeBSD, but not all module dependencies may be available and some functionality may be degraded.

**WARNING: Do not run the BBS as root!** Create a non-root user and configure the BBS to run as that instead. See :code:`lbbs -?` or :code:`/etc/lbbs/bbs.conf` to configure the run user and run group.

Sysoping
~~~~~~~~

Sysops can monitor and control the BBS using the sysop console provided by the :code:`mod_sysop` module. For example, you can list information about configured BBS menus, spy on nodes, or restart the entire BBS. Most commands are available by typing :code:`/` followed by a string, although some common commands are available by single-press hotkeys. Press :code:`?` in the console for a list of available options and commands.

If the BBS is started in the foreground, a sysop console is available on STDIN/STDOUT.

Additionally, regardless of how the BBS is started, the sysop console can be accessed remotely (so called since the access originates from outside the BBS process) by running the :code:`rsysop` program. This program is part of the external utilities and is installed to :code:`/var/lib/lbbs/external/rsysop`.

**WARNING:** Note that anyone that can access the :code:`rsysop` program is able to perform sysop tasks on the BBS. Even if the BBS is not running as root, it should be running under an account that is secured to the sysop.

System Configuration
~~~~~~~~~~~~~~~~~~~~

Configuration of LBBS and modules are done entirely through INI config files. Different parts of LBBS have their own config files, as does each module that uses one.
Config files go in :code:`/etc/lbbs` and sample configuration files exist in the :code:`configs` subdirectory of the source tree.
Each sample config file documents all available options. Refer to the sample configs for all relevant configuration.

A few especially important configuration files:

* :code:`bbs.conf` - key startup settings

* :code:`mail.conf` - Email configuration

* :code:`menus.conf` - BBS menus, menu items and options.

* :code:`mod_auth_mysql.conf` - MySQL/MariaDB auth provider module config

* :code:`mod_mail.conf` - General email server configuration

* :code:`mod_smtp_filter_dkim.conf` - DKIM signing

* :code:`modules.conf` - module loading settings (to disable a module, you do it here)

* :code:`net_smtp.conf` - SMTP server configuration

* :code:`net_ssh.conf` - SSH and SFTP server configuration

* :code:`nodes.conf` - Node-related configuration

* :code:`tls.conf` - SSL/TLS configuration

* :code:`transfers.conf` - File transfer configuration

Additionally, the MailScript rules engine uses a script file called :code:`.rules` in the user's root maildir or user's :code:`~/.config` (and :code:`before.rules` and :code:`after.rules` in the root maildir for global filtering) for manipulating messages.
A sample MailScript rules file is in :code:`configs/.rules` (though this is not a config file, but a sample rule script file).

User Configuration
~~~~~~~~~~~~~~~~~~

User configuration goes in :code:`~/.config`, which is a subdirectory of each user's BBS home directory (unrelated to any system home directories).

Users can edit these files either via the BBS shell (if configured by the sysop) or via any enabled file transfer protocols (e.g. FTP, FTPS, SFTP).

* :code:`.imapremote` - IMAP client proxy configuration

* :code:`.oauth.conf` - OAuth authentication configuration (used for IMAP client proxy and SMTP submission)

* :code:`.plan` - UNIX .plan file, used by the Finger protocol

* :code:`.project` - UNIX .project file, used by the Finger protocol. Limited to 1 line.

Network Login Services
~~~~~~~~~~~~~~~~~~~~~~

Network login or comm drivers are modules in the :code:`nets` source directory, responsible for implementing a network login service. These are what allow users to actually connect to the BBS itself.

Generally speaking, the comm drivers implement some kind of standardized TCP-based protocol. There are builtin drivers for Telnet, RLogin, and SSH. **Note that Telnet and RLogin are plain text protocols and thus insecure!** Using SSH is recommended for any public connections.

LBBS also includes a UNIX domain socket module (:code:`net_unix`). One use case for this is if you want to "proxy" connections to the BBS through the main, public-facing network login service. For example, say you run OpenSSH on port 22 (and you don't want to change the port), but you still want people to be able to connect to your BBS on port 22. You can create a public user account on your server that executes the BBS as a program, rather than providing a login shell. If you do this, you don't need any of the network drivers loaded or running besides :code:`net_unix` (UNIX domain sockets provide the least overhead for these kinds of loopback connections). That said, the UNIX domain socket driver is quite primitive. Using one of the other drivers, particularly the SSH driver, will provide a far superior experience.

Do note, should you choose to proxy connections in the manner described above, there are several important security implications of doing this that you *must* understand, or you open your system up to vulnerabilities. See the comments at the top of the source file :code:`nets/net_unix.c`

Unless you really know what you are doing, you are probably better off using LBBS's builtin network login services, rather than proxying the connection through your system's primary network login services. This will provide a more seamless user experience and mitigate potential security vulnerabilities described above.

Each comm driver handles window resizing in its own way.

* :code:`net_ssh` - full support for window size at login and resizing later

* :code:`net_telnet` - support for window size at login, but currently no support for resizing later (could be added as an enhancement)

* :code:`net_rlogin` - broken support for window size at login (doesn't work)

* :code:`net_unix` - no support for window size. UNIX domain sockets are similar to a raw TCP socket, there is no terminal protocol riding on top of the socket here. If you need (or want) window size support, use a different network comm driver.

None of the network comm drivers are mutually exclusive - you can enable as many or few as you want, and users can use whatever protocol they want to.

Generally speaking, for the reasons listed above, SSH is the recommended protocol. Apart from being the only protocol secure to use over the Internet, it also fully handles terminal resizing.

The BBS also comes with some network services that aren't intended for terminal usage, e.g. FTP, HTTP, IMAP, etc. See the :code:`nets` directory for a full listing.

Using mod_auth_mysql
~~~~~~~~~~~~~~~~~~~~

The BBS needs at least one authentication provider to be able to authenticate users.
`mod_auth_mysql` is an included module that authenticates users against a MySQL/MariaDB database.

You'll need to create a user for the database, if you haven't already::

    CREATE USER 'bbs'@'localhost' IDENTIFIED BY 'P@ssw0rdUShouldChAngE!';
    GRANT ALL PRIVILEGES ON bbs.* TO 'bbs'@'localhost';
    FLUSH PRIVILEGES;

Then, create a database called :code:`bbs` and a table called :code:`users` - the SQL to do so is in :code:`scripts/dbcreate.sql`.

Don't forget to also add your DB connection info to :code:`mod_auth_mysql.conf`!

FAQ
===

Can I try it out without installing anything?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sure! The reference installation of LBBS is the PhreakNet BBS, reachable at :code:`bbs.phreaknet.org`. Guest login is allowed.

How can I bind BBS services to privileged ports if it's not running as root?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you are running your BBS as a non-root user (which you *should*!), you may encounter errors binding to particular ports.
There are a few different methods you can use to bind to privileged ports (1 through 1023) when running the BBS as a non-root user.

The first is as simple as explicitly granting the BBS binary the right to do so, e.g.::

    sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/sbin/lbbs

This is the recommended approach if it works for you. If not, you can also explicitly allow
all users to bind to any ports that are at least the specified port number::

    sudo sysctl net.ipv4.ip_unprivileged_port_start=18

This example would allow any user to bind to ports 18 and above.
The lowest standard port number currently used by the BBS is 18 (FTP).

Note that this method is not as secure as the first method, but is likely to work even if other methods fail.

Finally, note that many systems already have daemons running on the standard ports, e.g.
sshd, telnetd, Apache web server, etc. If these are present, you will need to resolve the conflict, as only one
program can bind to a port at any given time.

How do I run the BBS as a service under systemd?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run :code:`make service`, and this will install the service file for systemd to use.

Can I run SSH and SFTP on the same port?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Yes (and, in fact, you must, if you wish to enable both).
Originally, SSH and SFTP were provided by 2 independent modules. They are now combined, allowing for same-port usage, which users expect.

What terminal emulators are supported?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Most common terminal emulators should work fine. The emulator's terminal type is used, if sent, and some terminal autodetection is also performed.

Some emulators are particularly good. Of all the well-known ones, these three terminal emulators are particularly recommended for BBSing on Windows:

* **SyncTERM** - Works well, looks nice. You **must** use the `newer 1.2 version <https://github.com/bbs-io/syncterm-windows/releases/tag/dev>`_. The more commonly downloaded 1.1 version has major bugs.
* **qodem** - Initial configuration slightly unintuitive, but otherwise works very well, with excellent support for non-standard display sizes. Set :code:`doorway_mode_on_connect = mixed` in :code:`%userprofile%\Documents\qodem\prefs\qodemrc.txt`.
* **PuTTY** (and forks, like KiTTY) - Works well, no known issues. Not "retro" at all, but does the job fine.

Most other terminal emulators tested tend to have various setup, compatibility, or runtime issues. In particular:

* **NetRunner** - Not recommended. Poorer support for ANSI escape sequences and Telnet options. Does not send a terminal type! Poor support for ncurses applications.

I see warnings about a terminal type not being in the terminfo database.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This typically happens for terminal emulators that report non-standard terminal types that are not installed by default on the system.
This can be resolved by installing the appropriate terminfo file. See :code:`scripts/server_setup.sh` for an example of adding :code:`syncterm` support in this manner.

What is the difference between :code:`door_chat` and :code:`door_irc`?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:code:`door_chat` is a fully self-contained, isolated chat module that can only be used from within the BBS.
:code:`door_irc` is an IRC client that can be used to connect to the local IRC server (provided by :code:`net_irc`) or to another IRC server.
In most cases, :code:`door_irc` is likely what you want; however, :code:`door_chat` can still be used on its own, if it meets your needs.

When using private namespace IRC channels, channel messages get sent to me as private messages.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is likely that your IRC client does not properly support all the standardized channel prefixes (#, &, +, and !).
Many clients only support the first two, if even that. Because of this limitation, you can override the prefix used
for the per-user namespace prefix near the top of :code:`include/net_irc.h`, by defining :code:`PRIVATE_NAMESPACE_PREFIX_CHAR` appropriately.
If your client only supports the # prefix properly, then unfortunately you cannot use this feature, unless you can fix your client.

The Discord relay seems to exit immediately after being started.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The bot you created likely doesn't have all the necessary permissions. Make sure "Privileged Gateway Intents" are enabled as appropriate.

I have multiple hostnames. Is SNI (Server Name Indication) supported?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Yes, LBBS supports SNI as both a client and a server. Refer to :code:`tls.conf` for configuration details.

How can I serve webpages using the embedded web server?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
There are 3 methods supported by the web server:

* Embedded server applications - these are dynamic applications that run within the BBS itself

* Static files - static files on disk that the web server sends to clients

* CGI (Common Gateway Interface) - CGI can be used to dynamically send a webpage from an external program

Embedded dynamic scripting engines (e.g. a la Apache HTTP server's mod_php) are not currently supported.

How does the container enviornment (isoexec handler) work?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The :code:`isoexec` handler creates the specified process in a separate namespace so that is isolated from the root namespace
in which the BBS is running. Essentially, it creates a container, similar to how technologies like Docker work.

This enhances security by providing isolation between your system and whatever may be executed within the environment,
such as a shell or other arbitrary program. For example, you can use this to provide users shell access on your BBS,
but without actually granting them access to the main filesystem.

The container does require that you provide a root filesystem for it to use. An example of how to do this is
in :code:`configs/menus.conf`. Please also read the caveats, notes, and warnings about :code:`isoexec` in the sample config file.

The :code:`isoroot` program in the :code:`external` directory also demonstrates how this functionality works in a standalone manner,
if you want to test your container environment separately.

How do I set up TLS certificates?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You will need to get TLS certificates from a certificate authority to support protocols that use TLS for encryption.

We recommend using a free certificate authority, like Let's Encrypt.

The below steps show how you can get free 3-month TLS certificates from Let's Encrypt that will renew automatically as needed.

There are multiple ACME clients you can use; Certbot is another one. acme.sh is used here because it's lightweight; certbot installs quite a bunch of stuff (like snapd) that you probably don't otherwise need or want.

The guidance here uses a webroot in the BBS itself. There is an option to use a port, but this is misleading; if you run the ACME client in standalone mode, the BBS web server CANNOT be running at the same time. While this may be fine initially, it will be problematic for renewals. The webroot method ensures that certificates can be renewed without issue, as long as the BBS is running.

Finally, certificates will be stored in /etc/letsencrypt (just like Certbot), rather than inside your home directory (the default). You can obtain a certificate for multiple hostnames at the same time (see example in step 4):

1. Enable HTTP (but not HTTPS (yet), which will fail without a TLS certificate configured) in :code:`net_http.conf`.

2. Start the BBS (or reload net_http if it's already running)

3. :code:`curl https://get.acme.sh | sh`

4. :code:`~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --always-force-new-domain-key --issue -w /home/bbs/www --cert-home /etc/letsencrypt -d example.com -d example.net -d example.org`

5. Run :code:`crontab -e` and inspect the :code:`--home` argument in the cron job that was added. It should be :code:`/etc/letsencrypt` (or whatever path you chose for :code:`--cert-home`). If not, update it.

6. Update permissions: :code:`chown -R bbs /etc/letsencrypt/ && chgrp -R bbs /etc/letsencrypt/`

7. Now, update :code:`tls.conf` with the path to the cert and key (cert key) that ACME spits out.

8. Restart the BBS for TLS changes to take effect. In the future, you can also run :code:`/tlsreload` to reload certificates without a full restart.

What format does the BBS use to store email?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The BBS mail servers use the maildir++ format. This is similar to what software like Dovecot and Courier use by default,
although certain implementation details may differ.

Does the BBS provide a sendmail binary, for submitting local mail?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

No, it does not. Consequently, you may see messages like this in your cron logs, for example:

:code:`(CRON) info (No MTA installed, discarding output)`

This is because cron did not detect :code:`/usr/bin/sendmail`, which is used by default to submit outgoing mail from outside of the local MTA.

Installing the actual :code:`sendmail` is overkill and not recommended, since it also includes the Sendmail MTA, which will conflict with LBBS.
However, you can install a lightweight client like :code:`ssmtp` or :code:`msmtp` (a more actively maintained variant) to do this.
You just need to ensure you install an SMTP client consistent with the Sendmail interface, so that programs expecting sendmail
will work properly.

If you install msmtp, be sure to `configure it system-wide <https://marlam.de/msmtp/msmtp.html#A-system-wide-configuration-file>`_.

The below is a good default :code:`/etc/msmtprc` for most systems::

   account default
   host 127.0.0.1
   port 25
   from root@example.com
   tls off
   logfile /var/log/msmtp.log

Make sure to substitute the default "from" address with something appropriate for your server.

Then, you can symlink msmtp to sendmail, and things should "just work": :code:`ln -s /usr/bin/msmtp /usr/sbin/sendmail`.

Can I check email using the terminal instead of using IMAP/POP3?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Yes, `evergreen <https://github.com/InterLinked1/evergreen>`_ is the officially recommended terminal mail client for LBBS.
The :code:`door_evergreen` module automatically wraps execution of the mail client as appropriate for usage within the BBS.

Does the BBS provide any kind of webmail access?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
You can use `wssmail <https://github.com/InterLinked1/wssmail>`_, a fast and efficient webmail client designed with the BBS's mail server in mind (but may be used with any mail server).
LBBS comes with the mod_webmail module, which is a backend module for wssmail.

Note that only the webmail backend is a BBS module. The corresponding webmail frontend is a required but separately maintained project. (In theory, the frontend could have multiple implementations as well.)

If you don't want to use mod_webmail, you can also use any other open source webmail package, e.g. SquirrelMail, RoundCube, etc. and that should work just fine.
SquirrelMail is extremely simple (no JavaScript used or required); RoundCube comes with more features and extensibility.
In particular, RoundCube comes with a built-in graphical ManageSieve editor, which can be useful for managing your Sieve scripts.

Do keep in mind that webmail offers significantly reduced functionality compared to a standard mail client (e.g. something in the Thunderbird family,
like Interlink/MailNews).

How do I fully set up the webmail service?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
You will need to set up both the frontend and the backend for the webmail.

The frontend refers to a frontend website that provides the user-facing HTML, CSS, and JavaScript.

The backend refers to a backend service which interfaces between the frontend and the IMAP/SMTP servers.

The backend is :code:`mod_webmail`, though it runs on top of :code:`net_ws`, which itself depends on
the BBS's web server modules. The frontend is a separate project as the frontend is not coupled to
the backend, other than through the requirement that the WebSocket interface be consistent with both.

No configuration is required of the backend. Only the frontend needs to be configured.

The frontend does not need to be run under the BBS's web server. For example, you can
run the frontend under the Apache HTTP web server, just like any other virtualhost. You'll want
to secure the site using TLS just like any other site if it's public facing.

Apart from the frontend site itself, you can also configure a WebSocket reverse proxy under Apache HTTP
to accept WebSocket upgrades on your standard HTTPS port (e.g. 443) and hand those off to the BBS WebSocket
server. That might look something like this::

   RewriteEngine On
   RewriteCond %{HTTP:Upgrade} =websocket [NC]
   RewriteRule /(.*)           ws://localhost:8143/webmail [P,L]

This example assumes Apache is running on 443 (or whatever client facing port),
and :code:`net_ws` is listening on port 8143. Note that this connection is
not encrypted, but this is a loopback connection so that does not matter.

Why use mod_webmail over a more popular, established webmail package?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Refer to the webmail package documentation for more information: https://github.com/InterLinked1/wssmail

Why is there a non-standard filtering engine (MailScript) included?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The MailScript filtering language was explicitly designed to be very simple to parse, unlike filtering languages with
slightly more complicated syntax, such as Sieve. MailScript also allows for basic testing of filtering primitives
independent of the filtering language used, which can be useful for testing. MailScript was added before Sieve support
was added due to the easier implementation.

Currently, some capabilities, such as executing system commands or processing outgoing emails, are only possible with MailScript, not with Sieve.
Although there are Sieve extensions to do this, the Sieve implementation in the BBS does not yet support this
(or rather, the underlying library does not). Eventually the goal is to have full feature parity.

It is recommended that Sieve be used for filtering if possible, since this is a standardized and well supported protocol.
MailScript is a nonstandard syntax that was invented purely for this software, so it is not portable to other mail servers.
However, if the current Sieve implementation does not meet certain needs but MailScript does, feel free to use that as well.
Both filtering engines can be used in conjunction with each other, and they each have their advantages depending on
the use case.

Where do Sieve and MailScript filter scripts reside?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sieve rules reside in one of two locations. For personal mailboxes, they rise in :code:`~/config/*.sieve` and can
also be edited by users directly using the ManageSieve protocol (net_sieve). For non-user mailboxes,
they reside in the maildir.

MailScript rules may reside in either a mailbox's maildir or in a user's :code:`~/.config/.rules` file. Originally,
only the maildir version existed, and this version can only be edited by the sysop since users do not have access
to their maildirs. Users can directly modify the version in their home directories, and both scripts are evaluated.
The maildir version still exists because in non-user associated mailboxes (e.g. shared mailboxes), this is the only
version that exists, as there is no corresponding home directory for the mailbox. If a maildir script exists,
it is executed before the rules in the user's home directory.

There are three passes of filtering performed:

1. Pre-mailbox pass. Useful for setting default actions.
2. Mailbox pass (only for messages that correspond to a mailbox, for example, messages accepted to relay to another server do not)
3. Post-mailbox pass. Useful for enforcing required actions.

The following are all the locations that can contain filter scripts:

* Global rules (can only be modified by the sysop)

  * :code:`$ROOT_MAILDIR/before.rules` - MailScript rules to run in pre-mailbox pass. Always executed.
  * :code:`$ROOT_MAILDIR/after.rules` - MailScript rules to run in post-mailbox pass. Always executed.
  * :code:`$ROOT_MAILDIR/before.sieve` - Sieve rules to run in pre-mailbox pass. Always executed.
  * :code:`$ROOT_MAILDIR/after.sieve` - Sieve rules to run in post-mailbox pass. Always executed.

* Mailbox rules, only for messages corresponding to a mailbox

  * :code:`$MAILDIR/.rules` - MailScript rules to run for mailbox. Always executed. Not user-editable.
  * :code:`~/.config/.rules` - MailScript rules to run for mailbox. Only exists for personal mailboxes. User-editable.
  * :code:`$MAILDIR/.sieve` - Active Sieve script (or symlink) for mailbox. Not user-editable, but for personal mailboxes, can be changed using the ManageSieve protocol.
  * :code:`~/.config/*.sieve` - All Sieve scripts for mailbox. Only exists for personal mailboxes. User-editable, including via ManageSieve protocol.

Note that :code:`$ROOT_MAILDIR` is not a real variable defined by the BBS, but here refers to the root maildir, the directory that contains all the individual mailbox maildirs.
Likewise for :code:`$MAILDIR` referring to the mailbox's maildir. :code:`~` refers to the user's home directory.
Finally, note that "always executed" should be interpreted as "always executed if the script exists, and unless a previous global rule terminated rules processing altogether".

How do I enable spam filtering?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There is a builtin module for SpamAssassin integration. SpamAssassin installation and configuration is largely beyond the scope of this document, but here is a decent quickstart:

Installation
------------

Install SpamAssassin: :code:`apt-get install -y spamassassin`. You do not need :code:`spamass-milter` since milters are not currently supported.

TIP: If you have multiple mail servers in an internal hierarchy, we recommend installing SpamAssassin on the "outermost" SMTP server, i.e. the one that receives mail directly from other MTAs on the Internet. This way, you have the ability to refuse acceptance of certain spam emails during the SMTP transaction itself (which is "cheap"), rather than accepting it, relaying it to a downstream server, determining the email should be rejected, and then having to generate a "bounce" messages, since the original connection has already been closed (which is "expensive", and not as reliable). The first server can run SpamAssassin, and downstream servers with user mailboxes can then actually do filtering based on the headers added previously by SpamAssassin.

Note that if the incoming mail server running SpamAssassin is hosted on DigitalOcean, you will need to `sign up for a DQS key and follow the instructions in order to make Spamhaus's DNSBLs functional <https://www.spamhaus.org/resource-hub/email-security/if-you-query-the-legacy-dnsbls-via-digitalocean-move-to-spamhaus-technologys-free-data-query-service/>`_.

Deployment Considerations
-------------------------
SpamAssassin is best used before-queue, since this prevents backscatter by ensuring spam results are available for filtering rules to use (allowing recipients to outright reject highly suspected spam, for instance). :code:`mod_spamassassin` invokes SpamAssassin during the SMTP delivery process to allow this.

When invoked directly (e.g. as :code:`/usr/bin/spamassassin`), SpamAssassin will read the message from the BBS on STDIN and output the modified message on STDOUT. Because the BBS only needs SpamAssassin to prepend headers at the top, it will *not* use the entire returned body from SpamAssassin. Instead, it will prepend all of the SpamAssassin headers and ignore everything else, since that would just involve copying the remainder of the message back again for no reason. This contrasts with with more conventional facilities that mail transfer agents provide for modifying message bodies on delivery.

Configuration
-------------

* Load the language plugin by adding :code:`loadplugin Mail::SpamAssassin::Plugin::TextCat` to :code:`/etc/spamassassin/local.pre`

* Create your custom preference file, e.g. :code:`/etc/spamassassin/config.cf`::

   # Required score to be considered spam (5 is the default, and should generally be left alone, fine tune your Junk threshold using mail filtering rules instead)
   required_score      5

   # English is the only language that won't trigger the UNWANTED_LANGUAGE_BODY rule
   ok_languages en

   # SPF hard fail, always reject
   score SPF_FAIL 10.0

   # SPF soft fail, always send to Junk
   score SPF_SOFTFAIL 5.0

   # Heavily penalize mail from domains with no SPF record
   score SPF_NONE 3.0

   # No valid author signature and from-domain does not exist
   score DKIM_ADSP_NXDOMAIN 5.0

   # No valid author signature, domain signs all mail and suggests discarding the rest (DISCARD)
   score DKIM_ADSP_DISCARD 5.0

   # No valid author signature, domain signs all mail (ALL)
   score DKIM_ADSP_ALL 5.0

   # Penalize missing DMARC policy
   score DMARC_MISSING 2.0

   # Email is not in English
   score UNWANTED_LANGUAGE_BODY 3.5

   # Penalize HTML only emails
   score MIME_HTML_ONLY 1.8

   # Penalize if HTML doesn't match plain text
   score MPART_ALT_DIFF_BODY 1.7

   # Penalize newly registered domains
   score FROM_FMBLA_NEWDOM 4.5
   score FROM_FMBLA_NEWDOM14 3.5
   score FROM_FMBLA_NEWDOM28 2.5

   # Penalized heavily abused freemail
   score FREEMAIL_FROM 0.5

   # Don't modify original message (apart from adding headers)
   report_safe 0

   # Add X-Spam-Report to all emails, including ham, not just spam
   add_header all Report _REPORT_

   # Add X-Spam-Score to all emails, including ham, not just spam
   add_header all Score _SCORE_

   # Bayes DB (specify a path and sa-learn will create the DB for you)
   bayes_path /var/lib/spamassassin/bayesdb/bayes

If you choose not to sign up for a DQS key as described above, SpamHaus may reject your RBL/URIBL requests, in which case you can disable RBL/URIBL checks by adding::

   # Skip RBL checks
   skip_rbl_checks 1

   # Skip URIBL checks
   skip_uribl_checks 1

* Go ahead and run :code:`sa-compile` to compile your rule set into a more efficient form for runtime (if you modify :code:`config.cf` in the future, rerun this command).

To regularly update SpamAssassin with the latest rules, enable the cron job by adding :code:`CRON=1` to :code:`/etc/default/spamd`.

Filtering Spam
--------------

SpamAssassin will tag spam appropriately, but not do anything to it. That's where filtering rules can help filter spam to the right place (or even reject it during the SMTP session). There are a few headers that SpamAssassin will add, e.g. :code:`X-Spam-Level`. Users can customize what they want to do with spam and their threshold for spam filtering using a filter. The most common rule is to move suspected spam to the user's Junk folder.

Our recommendation is to ignore the :code:`X-Spam-Flag` header entirely. Instead, you can use the :code:`X-Spam-Level` header in mail filtering rules to handle spam, by either moving them to Junk (at a lower threshold) and outright rejecting them (at a higher threshold). This gives you much more fine-grained control, and allows different users to customize their filtering.

The :code:`X-Spam-Level` header contains one asterisk for each whole positive spam score level (i.e. it is the value of the spam score (also available directly in the :code:`X-Spam-Score` header), rounded down, and empty if less than 1.0, including negative. For instance, :code:`****` denotes the message has a spam score of between 4.0 and 4.9. Since spammier messages have more :code:`*`s, you can easily use a simple substring match on this header value, for example::

   # This MailScript rule will outright reject any messages with a spam score of 10.0 or greater (and set a custom refusal message)
   RULE
   MATCH DIRECTION IN
   MATCH HEADER X-Spam-Level CONTAINS **********
   ACTION REJECT Message refused, appears to be spam
   ENDRULE

   # This MailScript rule will move any messages with a spam score of 5.0 or greater (and implicitly 9.9 or less, if the above rule is present) to the user's Junk folder
   RULE
   MATCH DIRECTION IN
   MATCH HEADER X-Spam-Level CONTAINS *****
   ACTION MOVETO Junk
   ENDRULE

You could also use a standard Sieve rule instead of a MailScript rule::

   require "fileinto";
   if header :contains "X-Spam-Level" "*****" {
      fileinto "Junk";
   }

Note that :code:`X-Spam-Level` only gives you the ability to filter by intervals of 1. If you want more granular control than that, you should use the :code:`X-Spam-Score` header instead::

   # This MailScript rule will reject any messages with a spam score of 7.7 or greater
   RULE
   MATCH DIRECTION IN
   MATCH HEADER X-Spam-Score >= 7.7
   ACTION REJECT
   ENDRULE

Both Sieve and MailScript rules can also be configured globally (system-wide), in addition to per-mailbox. This is useful if you as the postmaster want to reject all mail above a certain spam level. There are two global Sieve scripts that can be configured and one global MailScript script. All of these files must be named as follows and placed in the root maildir:

* :code:`before.sieve`: Sieve rules that will be executed before any per-mailbox rules are executed. This is usually better for default settings that users may override, such as moving spam to Junk.
* :code:`after.sieve`: Sieve rules that will be executed after any per-mailbox rules are executed. This is usually better for settings that you do not want users to override.
* :code:`before.rules`: MailScript rules that will be executed before any per-mailbox rules. This is usually better for default settings that users may override, such as moving spam to Junk.
* :code:`after.rules`: MailScript rules that will be executed after any per-mailbox rules. This is usually better for settings that you do not want users to override.

The order with which Sieve and MailScript rules run with respect to each other is consistent between rule engines, e.g. both global Sieve and MailScript "before" rules will run before any per-mailbox rules, which will run before any global "after" rules. The order with which Sieve and MailScript rules are evaluated within a single pass (e.g. the before rules) is not defined and should not be relied upon.

One special case that can only be handled in MailScript is filtering outbound mail. The Sieve implementation does not currently support this. A special case of outbound filtering that may be useful is refusing acceptance of spam in a multi-server mail network. If your primary incoming mail server runs SpamAssassin (as recommended), but user mailboxes reside on another server downstream, then normal user mail filtering to outright refuse definite spam messages normally wouldn't be performed until the message is delivered to the local mail server, by which time the incoming server has already accepted the message, only for it later to be rejected, requiring a bounce to be generated. To work around this, you can configure a global MailScript rule to refuse acceptance of confirmed spam. The downside to this approach is users no longer have the ability to override this, since the rule is being run on a different server. Therefore, use caution and only refuse messages with a very high probability of being spam (e.g. spam score of 10 or greater). This could be done as follows::

   # This MailScript rule will reject any messages with a spam score of 10 or greater
   RULE
   MATCH DIRECTION OUT
   MATCH HEADER X-Spam-Score >= 10
   ACTION REJECT
   ENDRULE

Note this is similar to an above rule, except the direction is :code:`OUT`. For incoming mail, this rule will only be executed for mail that is accepted and sent onwards to another server. (It could also apply for local submissions that are sent to external parties, though such mail shouldn't have an :code:`X-Spam-Score` header at this point, so this is unlikely to cause an issue.) Note, however, that not all filter actions apply to all mail; for example, in the case of mail accepted by an edge server and then relayed to another server housing the actual mailbox, no mailbox exists locally on the edge server for the message while it is being processed. Mailbox rules thus cannot be run on these messages, but global rules (before/after Sieve and MailScript rules) can still be run. Certain actions, like REJECT, can be used without issue, while some actions, such as :code:`fileinto` (Sieve) or :code:`MOVETO` (MailScript) cannot be used since there is no corresponding mailbox within which to move messages (if such rules are, they will be ignored and trigger a warning). Currently, in Sieve, it is not actually possible to target such mail; in MailScript, the condition :code:`MATCH DIRECTION IN` should currently suffice to ensure the rule is skipped for non-mailbox mail.

The :code:`mod_smtp_recipient_monitor` plugin module also performs outbound filtering. If the :code:`.config/.recipientmap` file exists in a user's home directory, this module will automatically screen outbound mail and warn the user if sending mail to a brand-new from/recipient combination. This can help prevent mail from accidentally being sent to the wrong users, or from the wrong email address.

Training
--------

SpamAssassin can work reasonably well out of the box, but will get better with training. It is best trained on real spam (and ham, or non-spam) messages. You can tell SpamAssassin about actual spam (:code:`sa-learn --spam /path/to/spam/folder`) or ham (:code:`sa-learn --ham /path/to/ham/folder`).

If you receive spam, don't delete them - put them in a special folder (e.g. Junk) and rerun :code:`sa-learn` periodically.

You can also run on multiple folders - careful though, if users have a filter to move suspected spam to Junk, this could train on false positives if this is run before they react and correct that. Therefore, if your mail server is small, you may just want to do this manually periodically after receiving Spam::

   sa-learn --spam /home/bbs/maildir/*/Junk/{cur,new}
   sa-learn --ham /home/bbs/maildir/*/cur

Once you've trained the Bayes model, you can delete the spam messages if you wish. Rerunning the model on existing messages is fine too - the model will skip messages it's already seen, so there's no harm in not deleting them immediately, if you have the disk space.

Email sent from the BBS keeps going to people's spam!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Email deliverability is beyond the scope of this guide, but there are a few things you'll want to ensure:

* SPF records are configured for any domains from which you send email

* MX records are configured for any domains from which you send email

* rDNS is configured for any IP addresses from which you send email (used for FCrDNS). If you use DigitalOcean, your `Droplet name must be the rDNS hostname <https://docs.digitalocean.com/products/networking/dns/how-to/manage-records/#ptr-rdns-records>`_. The rDNS hostname must resolve to your IP but does not need to match your mail domain, nor encompass all of them.

* DKIM is configured (see :code:`mod_smtp_filter_dkim.conf`)

Additionally, there are many online tools that can do some deliverability checks for you, which may catch common configuration errors and mistakes:

* `Mail Tester <https://www.mail-tester.com>`_

* `Postmastery <https://www.postmastery.com/email-deliverability-test/>`_

How can I improve the efficiency of my email submissions?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You *could* use RFC 4468 BURL, but this is not supported by virtually any mail client (besides Trojita).

The recommended setting is to use MailScript rules to "filter" your outgoing emails.
You can define a rule for each account to save a copy in your IMAP server's Sent folder.
For your local BBS email account, you can use :code:`MOVETO Sent`; for remote IMAP servers,
you can specify an IMAP URL like :code:`MOVETO imaps://username@domain.com:password@imap.example.com:993/Sent`.
The BBS's SMTP server will then save a copy of the message in the designated location before relaying or sending it.

This can be faster since normally your mail client uploads messages twice: once to your SMTP server to send it,
and once to the IMAP server to save a copy of it (in the Sent folder). BURL IMAP was created to address this inefficiency,
but unfortunately lacks widespread client support (although LBBS and several other IMAP servers do support it).
Instead, the SMTP server can save the copy to the IMAP server (basically the inverse of BURL).
(Gmail's SMTP server does something like this as well.) This doesn't require any special client support.

If you synchronize your Sent folder locally, you'll still end up downloading the message, but it'll use your download bandwidth
instead of your uplink bandwidth, the latter of which is typically more limited.

If you do have the SMTP server save copies of your sent messages, make sure to *disable* "Save a copy of sent messages to..." in your mail client, to avoid saving a duplicate copy.

As noted above, currently Sieve and MailScript do not have feature parity, so you cannot use Sieve to do this; you must use MailScript rules.

Donations
=========

LBBS is developed entirely by volunteers on their own time.

If LBBS is useful to you, please `consider donating <https://interlinked.us/donate>`_ to fund further development and features. Thank you!

Licensing
=========

If you intend to run an LBBS system or make modifications to LBBS, you must understand the license.

LBBS is licensed under the `GNU General Public License version 2 (GPLv2) <https://choosealicense.com/licenses/gpl-2.0/>`_. At a high level, GPLv2 is a copyleft license (sometimes referred to as a more restrictive license) that requires that any modifications to the source code be distributed to any users to whom the resulting program is made available. This contrasts with more permissive licenses such as the Apache License or MIT License that do not have such requirements. See the link for more details.

There are a few reasons I opted to license LBBS under the GPL, some out of choice, others less so:

* The reality is that the days of commercial BBSes are long over. There is no money in running a BBS these days, nor is there any money in writing BBS software. LBBS is no exception. The majority of BBS users, sysops, and developers are all hobbyists doing this for fun, not to make a living. A copyleft license better suits the environment of BBSes today, encouraging contributors to share modifications and improvements with the community.

* I considered licensing the LBBS core under the Affero General Public License (AGPL) and modules under the GPL, since BBS users are not entitled to the source code under the GPL unless the binaries are distributed to them. However, it was (and is) important to me that modules not be licensed under the AGPL, but something more permissive such as the GPL, so that sysops and developers could create their own custom modules and not be required to disclose the source code to their users, in order to provide more freedom for users and sysops. Rather than complicating things with split-licensing, licensing everything under the more permissive GPL is simpler.

* Parts of the LBBS source code and binary have dependencies on components that are themselves licensed under the GPL. For example, the history functionality for the sysop command line, which depends on :code:`history(3)`, a component of the GNU readline library (licensed under the GPL). So, LBBS is required to be licensed with a copyleft license at least as strong as the GPL.

Note that these are merely the rationales for licensing this project under GPLv2, but the vast majority of users and sysops do not need to be concerned about the license, unless you intend to distribute compiled versions of LBBS or make modifications to it. If you make modifications to the source and distribute the result, you must make the source code available under a license at least as restrictive as the GPLv2. If you are merely using LBBS or are a sysop running LBBS, then there is nothing special you need to do to comply with the GPL. Obviously, this is not legal advice, and you should consult a lawyer if you have licensing questions or concerns.

Development Notes
=================

Architecture
~~~~~~~~~~~~

LBBS is a single-process multithreaded program. The BBS "core" is the :code:`lbbs` binary comprised of all the source files in the :code:`bbs` directory. The core is designed to be small, with additional functionality provided by modules that can be dynamically loaded and unloaded as desired. This makes it easy for functionality to be added in a self-contained manner.

For example, the sysop console is provided by the :code:`mod_sysop` module. It is not built in to the core. This makes it easy to modify the sysop console, and you could even write your own sysop console and use that instead!

This approach is also relied on for key functionality that could be implemented in different ways. For example, the :code:`mod_auth_mysql` is an *authentication provider* that can process user login requests, backed by a MySQL/MariaDB database. However, maybe you use a PostgreSQL database instead, or SQLite, or some other kind of authentication mechanism entirely. LBBS doesn't dictate that users be stored in a certain type of file on disk, or even locally at all. Since auth providers can use any DBMS, API, etc. you could easily set up a BBS server fleet, all sharing the same users. The point is authentication is handled in a very flexible manner. (Obviously, somebody will need to write a module to handle authentication the way you want to, but this can be done without touching the BBS core at all.)

At a high level, incoming connections are accepted by a network comm driver using a socket. The connection is accepted and each network driver does its own preliminary handling of the connection, such as getting the terminal size. Then, a thread is spawned to handle the node and a pseudoterminal (PTY) is created, with the master side connected to the socket file descriptor and the slave side used for all node I/O. For example, to put the terminal in non-canonical mode or enable/disable echo, these operations are performed on the slave side of the node's PTY.

Some network drivers, such as :code:`net_ssh` currently create a pseudoterminal internally, such that the master end of the SSH pseudoterminal is connected to the libssh file descriptor, and the slave side is used as the node's master PTY fd (as opposed to the socket fd directly).

LBBS does not use ncurses to draw to the screen, partly for simplicity, and partly because ncurses is not multithread safe. While it is possible to compile ncurses such that it has support for threading, this version is not highly portable or often used, and even the maintainer of ncurses discourages using it. Instead, menus are generally generated dynamically directly by LBBS, based on the node's terminal dimensions, although sysops may also manually create menus that are displayed instead.

Menus are the heart of the BBS and where a lot of the action is, both for users and from an architecture perspective. After a user logs in, the BBS node is dropped into the menu routines which handle all the work of generating and displaying menus and options, reading options from users, and taking the appropriate action, such as executing a program, another module, or displaying a submenu.

Directory Structure
~~~~~~~~~~~~~~~~~~~

Most code is documented using doxygen, and each source file describes its purpose. The LBBS source is organized into several key directories:

* :code:`bbs` - Source files that comprise the main :code:`lbbs` binary. This is the "BBS core".

* :code:`configs` - Sample config files for LBBS modules and settings

* :code:`doors` - Door modules (both internal and external doors). In BBSing, the concept of a "door" refers to an interface between the BBS and an external application, used to access games, utilities, and other functionality not part of the BBS program itself. In LBBS, door modules are actually BBS modules, but they are not part of the BBS core, so are external in that sense only. Door modules can call LBBS functions, however, and run within the BBS process, so LBBS door modules offer enhanced functionality beyond that provided with a raw door. To execute a true external program, use :code:`exec` rather than :code:`door` in :code:`menus.conf`.

* :code:`external` - External programs that are not part of the BBS itself, but may be useful supplements or programs to use in conjunction with it. For example, these can be executed as external programs from within the BBS, but they could also be run on their own.

* :code:`include` - Header files for core files

* :code:`modules` - General modules

* :code:`nets` - Network login services / communication driver modules

* :code:`scripts` - Useful scripts for use with LBBS

* :code:`terms` - Reserved for possible future terminal modules, not yet used

* :code:`tests` - Test framework for black box testing

LBBS, once installed, uses several system directories:

* :code:`/etc/lbbs/` - config files

* :code:`/usr/sbin/lbbs` - LBBS binary

* :code:`/usr/lib/lbbs/modules/` - shared object modules

* :code:`/var/lib/lbbs/` - General LBBS resources

  * :code:`/var/lib/lbbs/external` - External programs
  * :code:`/var/lib/lbbs/scripts` - Useful scripts for use with LBBS

* :code:`/var/log/lbbs/` - log directory

Additionally, modules (e.g. the mail server, newsgroup server, etc.) may use their own directories for storing data. These directories are configurable.

Make Targets
~~~~~~~~~~~~

You can compile and link all the files in a directory containing source files simply by specifying the directory, e.g.:

* :code:`make bbs`

* :code:`make doors`

* :code:`make modules`

* :code:`make nets`

To compile everything, run :code:`make all`, or simply :code:`make`.

To install the LBBS binary, all shared object modules, and all external programs, run :code:`make install`.

To create the config directory with sample configuration files, run :code:`make samples`.

To delete all compiled code to ensure all source code is cleanly recompiled, run :code:`make clean`.

Some targets are also included to aid developers in debugging the BBS or sysops in tracking down bugs. You will need valgrind installed (:code:`apt-get install valgrind`):

* :code:`make valgrind` - Run valgrind and log all results to :code:`valgrind.txt`. If you suspect a memory leak, you must attach this file when opening an issue.

* :code:`make valgrindsupp` - Generate suppression list from valgrind findings. You should not do this without a good understanding of the findings from the previous step.

* :code:`make valgrindfd` - Run valgrind but show findings in the foreground, rather than redirecting them to a log file.

* :code:`make helgrind` - Run helgrind in the foreground. This is useful for debugging locking.

Most stuff is commented for doxygen. You can generate the doxygen docs by running :code:`make doxygen` (you may need to run :code:`apt-get install -y doxygen graphviz` first)

Debugging
~~~~~~~~~

LBBS includes a number of builtin tools to assist with debugging, in addition to using :code:`valgrind` as described above. You can turn on debugging by using the :code:`-d` option on startup (up to 10 :code:`d`'s), setting a debug level in :code:`bbs.conf`, or changing the debug level at runtime using the :code:`/debug` command. **If you submit an issue, you must provide full debug (:code:`debug=10`)**.

From the sysop console, you can run :code:`/threads` to show running threads, helpful if you suspect threading-related issues. Running :code:`/fds` will show all open file descriptors.

Tests
-----

LBBS includes unit tests for functionality that can be tested individually. These can be run using :code:`/runtests` from the sysop console.

A test framework is also included for black box testing of modules. The tests can be compiled using :code:`make tests` and run using :code:`tests/test` from the source directory.
To run just a specific test, you can use the :code:`-t` option: consult the help (:code:`tests/test -?`) for program usage.

Note that although the tests use isolated configuration and runtime directories, they currently do not log to a separate log file, so you may wish to avoid running the test framework on a production system to avoid any "mingling" of test executions and normal production usage. The test framework will also stop the BBS before running, so it is best run in a dedicated development environment.

The test framework will return 0 if all tests (or the specified test) completed successfully and nonzero if any test(s) failed.

Dumper Script
-------------

The :code:`/var/lib/lbbs/scripts/bbs_dumper.sh` script can be helpful when trying to get backtraces of LBBS.

Usage:

* :code:`./bbs_dumper.sh pid` - Get PID of running BBS process

* :code:`./bbs_dumper.sh term` - Terminate running BBS process (SIGKILL)

* :code:`./bbs_dumper.sh term` - Quit running BBS process (SIGQUIT)

* :code:`./bbs_dumper.sh postdump` - Obtain a backtrace from a core dump file

* :code:`./bbs_dumper.sh livedump` - Obtain a backtrace from a currently running LBBS process

Note that if the BBS was compiled with optimizations enabled (anything except -O0, e.g -Og, -O1, -O2, -O3), then some variables may be optimized out in the backtrace.
If you submit an issue, please recompile the BBS without optimization (change to :code:`-O0` in the top-level Makefile) and get a backtrace from an unoptimized system. Otherwise, important details may be missing as the backtrace is incomplete.

If you are not getting core dumps, ensure the current directory (in which the BBS was started or is currently running) is writable by the BBS user. Otherwise, it cannot dump a core there.

ABI Compatibility
~~~~~~~~~~~~~~~~~

Some projects strive to preserve ABI (Application Binary Interface) compatibility as much as possible when making changes (e.g. no breaking ABI changes allowed within a major revision).

While it is certainly not an objective to break ABI, it should be preferred to break ABI if necessary when making changes (e.g. adding
arguments to a function) when doing it a different way would result in less maintainable or clunkier code in the long run.

For example, if the original function is still useful, it can still call the new function under the hood (which would preserve ABI), but if not,
the original prototype should simply be expanded.

Likewise, when adding members to a struct (which can break ABI if not placed at the end), members should be added at the most logical place,
not necessarily at the end.

In essence, changes will not strive to preserve ABI if that is the sole purpose of making a change a particular way.

The implication of this development philosophy is that users *should not expect* any ABI compatibility between versions from different points in time.
Mixing files from different source revisions may result in an unstable system. You should always fully recompile LBBS from source when building
a new or updated version.

To make it easier for people to keep track of breaking changes, the following policies should be adhered to:

- If any ABI compatibility (i.e. C code) is broken, at least the minor version number (and possibly the major one) *must* be incremented.

- In general, if any user-facing functionality becomes backwards-incompatible, the major version number *must* be incremented.

Coding Guidelines
~~~~~~~~~~~~~~~~~

Please follow the coding guidelines used in this repository. They are by and large K&R C, importantly:

* Use tabs, not spaces.

* Indent properly. Functions (only) should have the opening brace on their own line.

* Braces denoting code blocks are always required, even for single-statement if, for, while, etc. where the braces are technically optional.

* Use :code:`/* multi-line C89 */` comments only, not :code:`// single-line C99 comments`.

* Trim all trailing whitespace.

* All public functions (anything in header files) should be documented using doxygen.

* Add unit tests if possible (modules only).

* For complex functionality, add black box tests in the test framework.

* Avoid C functions that are not multi-thread safe.

* Do not typedef structs

* If there is a BBS function to do something, use it. (e.g. use the :code:`bbs_pthread_create` wrapper, not :code:`pthread_create` directly).

* All source files should use UNIX line endings (LF). However, config files should use DOS/Windows line endings (CR LF). This is so that if Windows users open a config file in an old version of Notepad, it displays properly.
