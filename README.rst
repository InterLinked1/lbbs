============================================
LBBS - The Lightweight Bulletin Board System
============================================

.. contents:: Contents
.. section-numbering::

Welcome! Whether you're new to BBSing or a veteran sysop, LBBS was written to be a highly configurable, modular BBS for developers, sysops, and users alike.

LBBS is a BBS (bulletin board system) package and personal server written from the ground up to be extensible, modular, and, of course, lightweight. The codebase is relatively small (~50K SLOC), with relatively few dependencies. It is designed to be easy for sysops to administer, easy for users to use and navigate, and easy for developers to read, understand, maintain, and contribute to the source code.

Features
========

Key features and capabilities include:

* Fast and lightweight, written entirely in C

* Terminal access via Telnet, RLogin, SSH, and UNIX domain socket support *(note that Telnet and RLogin are plain text protocols and thus insecure)*

* File transfers via FTP, SFTP, Gopher, and HTTP/HTTPS

* User home directories

* Container environment for executing programs

* Password and public key authentication

* Config-file driven configuration

* Submenu "skip menu navigation" - select options in multiple nested menus at once
* Automatic menu screen generation and resizing
* Electronic mail (SMTP, POP3, IMAP4)

  * Aliases
  * Mailing lists
  * Mailbox quotas
  * Shared mailboxes and ACL controls
  * RFC 4468 BURL IMAP and server-side proxied append support, for more efficient (bandwidth saving) email submission
  * Remote mailboxes (IMAP proxy)

    * Built-in OAuth2 proxy, allowing the BBS to log in to remote IMAP servers using OAuth2, while your IMAP client uses your normal BBS credentials

  * Filtering

    * Sieve filtering scripts and ManageSieve service
    * `MailScript filtering engine <configs/.rules>`_ for flexible, custom, dynamic mail filtering rules (Sieve alternative)

* Newsgroups (NNTP)

* Native realtime chat

* Internet Relay Chat client and server (including ChanServ), with native IRC and Discord relays

* Emulated slow baud rate support

* TDD/TTY (telecommunications device for the deaf) support

* Sysop capabilities
  * Node spying
  * Kick nodes

Usage
=====

Installations
~~~~~~~~~~~~~

To install LBBS, you will need to compile it from source. Fortunately, we've made this as easy as possible::

     cd /usr/src
     git clone https://github.com/InterLinked1/lbbs.git
     cd lbbs
     ./install_prereq.sh
     make
     make install
     make samples

To start the BBS with the sysop console in the foreground, you can then run :code:`lbbs -c`. To daemonize it, just run :code:`lbbs`.

At the console, press :code:`?` or :code:`h` for a list of available commands. You can also run :code:`lbbs -?` or :code:`lbbs -h` for a list of startup options.

Some configuration of the BBS will be needed before you can use it. Consult the sample configs in :code:`/etc/lbbs` for an overview of settings you may need to configure. At a minimum, you will need to add a menu to the BBS (:code:`menus.conf`).

LBBS is best run on a modern version of Debian Linux (Debian 10 or Debian 11). Note that LBBS likely is not currently portable to non-Linux systems, e.g. BSD or UNIX. It likely won't be a lot of work to make it more portable, but that work hasn't been done yet since I only test and run BBSes on Linux. Additionally, LBBS requires gcc to compile, since it uses some gcc-specific compiler extensions.

**WARNING: Do not run the BBS as root!** Create a non-root user and configure the BBS to run as that instead. See :code:`lbbs -?` or :code:`/etc/lbbs/bbs.conf` to configure the run user and run group.

Sysoping
~~~~~~~~

Sysops can monitor and control the BBS using the sysop console provided by the :code:`mod_sysop` module. For example, you can list information about configured BBS menus, spy on nodes, or restart the entire BBS. Most commands are available by typing :code:`/` followed by a string, although some common commands are available by single-press hotkeys. Press :code:`?` in the console for a list of available options and commands.

If the BBS is started in the foreground, a sysop console is available on STDIN/STDOUT.

Additionally, regardless of how the BBS is started, the sysop console can be accessed remotely (so called since the access originates from outside the BBS process) by running the :code:`rsysop` program. This program is part of the external utilities and is installed to :code:`/var/lib/lbbs/external/rsysop`.

**WARNING:** Note that anyone that can access the :code:`rsysop` program is able to perform sysop tasks on the BBS. Even if the BBS is not running as root, it should be running under an account that is secured to the sysop.

Configuration
~~~~~~~~~~~~~

Configuration of LBBS and modules are done entirely through INI config files. Different parts of LBBS have their own config files, as does each module that uses one.

Config files go in :code:`/etc/lbbs` and are as follows:

* :code:`bbs.conf` - key startup settings

* :code:`door_irc.conf` - IRC clients

* :code:`mail.conf` - Email configuration

* :code:`menus.conf` - BBS menus, menu items and options. **This is the heart of LBBS configuration.**

* :code:`mod_auth_mysql.conf` - MySQL/MariaDB auth provider module config

* :code:`mod_auth_static.conf` - Static user configuration (intended for development and testing)

* :code:`mod_chanserv.conf` - ChanServ IRC service config

* :code:`mod_discord.conf` - Discord/IRC relay configuration

* :code:`mod_mail.conf` - General email server configuration

* :code:`mod_oauth.conf` - OAuth2 token configuration

* :code:`mod_relay_irc.conf` - IRC/IRC relay configuration

* :code:`modules.conf` - module loading settings (to disable a module, you do it here)

* :code:`net_finger.conf` - Finger protocol config

* :code:`net_ftp.conf` - FTP (File Transfer Protocol) server config

* :code:`net_gopher.conf` - Gopher server config

* :code:`net_http.conf` - HTTP/HTTPS web server config

* :code:`net_imap.conf` - IMAP4 server config

* :code:`net_irc.conf` - Internet Relay Chat server config

* :code:`net_nntp.conf` - Network News Transfer Protocol (NNTP) server config

* :code:`net_pop3.conf` - POP3 server config

* :code:`net_rlogin.conf` - RLogin server configuration

* :code:`net_smtp.conf` - SMTP server configuration

* :code:`net_ssh.conf` - SSH and SFTP server configuration

* :code:`net_telnet.conf` - Telnet server configuration

* :code:`nodes.conf` - Node-related configuration

* :code:`tls.conf` - SSL/TLS configuration

* :code:`transfers.conf` - File transfer configuration

* :code:`variables.conf` - Global variable configuration

Each sample config file documents all available options. Refer to the sample configs for more info about a file.

Additionally, the MailScript rules engine uses a script file called :code:`.rules` in the root maildir and the user's root maildir for manipulating messages.
A sample MailScript rules file is in :code:`configs/.rules` (though this is not a config file, but a sample rule script file).

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

The BBS also comes with some network services that aren't intended for terminal usage, e.g.:

* :code:`net_finger` - Finger server

* :code:`net_ftp` - File Transfer Protocol server

* :code:`net_gopher` - Gopher server

* :code:`net_http` - HTTP/HTTPS web server

* :code:`net_imap` - IMAP server

* :code:`net_irc` - Internet Relay Chat server

* :code:`net_nntp` - Network News Transfer Protocol (NNTP) server

* :code:`net_pop3` - POP3 server

* :code:`net_smtp` - Simple Mail Transfer Protocol (SMTP) server

* :code:`net_sftp` - Secure File Transfer Protocol server

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
~~~~~~~~~~~~~~~~~

Sure! The reference installation of LBBS is the PhreakNet BBS, reachable at :code:`bbs.phreaknet.org`. Guest login is allowed.

How can I bind BBS services to privileged ports if it's not running as root?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you are running your BBS as a non-root user (which you *should*!), you may encounter errors binding to particular ports.
There are a few different methods you can use to bind to privileged ports (1 through 1023) when running the BBS as a non-root user.

The first is as simple as explicitly granting the BBS binary the right to do so, e.g.::

    sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/sbin/lbbs

This is the recommended approach if it works for you. If not, you can also explicitly allow
all users to bind to any ports that are at least the specified port number::

    sudo sysctl net.ipv4.ip_unprivileged_port_start=21

This example would allow any user to bind to ports 21 and above.
The lowest standard port number currently used by the BBS is 21 (FTP).

Note that this method is not as secure as the first method, but is likely to work even if other methods fail.

Finally, note that many systems already have daemons running on the standard ports, e.g.
sshd, telnetd, Apache web server, etc. If these are present, you will need to resolve the conflict, as only one
program can bind to a port at any given time.

How can I run SSH and SFTP on the same port?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Currently, this is not possible, but hopefully this limitation will be fixed soon.

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

What format does the BBS use to store email?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The BBS mail servers use the maildir++ format. This is similar to what software like Dovecot and Courier use by default,
although certain implementation details may differ.

Does the BBS provide any kind of webmail access?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Not natively, no.
However, you can use an open source webmail package, e.g. SquirrelMail, RoundCube, etc. and that should work just fine.
SquirrelMail is extremely simple (no JavaScript used or required); RoundCube comes with more features and extensibility.
In particular, RoundCube comes with a built-in graphical ManageSieve editor, which can be useful for managing your Sieve scripts.

Do keep in mind that webmail offers significantly reduced functionality compared to a standard mail client (e.g. something in the Thunderbird family,
like Interlink/MailNews).

Why is there a non-standard filtering engine (MailScript) included?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The MailScript filtering language was explicitly designed to be very simple to parse, unlike filtering languages with
slightly more complicated syntax, such as Sieve. MailScript also allows for basic testing of filtering primitives
independent of the filtering language used, which can be useful for testing. MailScript was added before Sieve support
was added due to the easier implementation.

Currently, some capabilities, such as executing system commands or processing outgoing emails, that are only possible with MailScript, not with Sieve.
Although there are Sieve extensions to do this, the Sieve implementation in the BBS does not yet support this
(or rather, the underlying library does not). Eventually the goal is to have full feature parity.

Sieve rules can be edited by users directly using the ManageSieve protocol (net_sieve).
In contrast, MailScript rules can only be modified by the sysop directly on the server. Additionally,
MailScript allows for potentially dangerous operations out of the box, and should not normally be exposed to users.

It is recommended that Sieve be used for filtering if possible, since this is a standardized and well support protocol.
MailScript is a nonstandard syntax that was invented purely for this software, so it is not portable anywhere else.
However, if the current Sieve implementation does not meet certain needs but MailScript does, feel free to use that as well.
Both filtering engines can be used in conjunction with each other.

How can I improve the efficiency of my email submissions?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You *could* use RFC 4468 BURL, but this is not supported by virtually any mail client (besides Trojita).

The recommended setting is to use MailScript rules to "filter" your outgoing emails.
You can define a rule for each account to save a copy in your IMAP server's Sent folder.
For your local BBS email account, you can use :code:`MOVETO .Sent`; for remote IMAP servers,
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