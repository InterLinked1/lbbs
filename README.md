# LBBS - The Lightweight Bulletin Board System

Welcome! Whether you're new to BBSing or a veteran sysop, LBBS was written to be a highly configurable, modular BBS for developers, sysops, and users alike.

LBBS is a BBS server program written from the ground up to be extensible, modular, and, of course, lightweight. The codebase is relatively small, with relatively few dependencies. It is designed to be easy for sysops to administer, easy for users to use and navigate, and easy for developers to read, understand, maintain, and contribute to the source code.

Key features and capabilities include:

- Fast and lightweight, written entirely in C

- Terminal access via Telnet, RLogin, SSH, and UNIX domain socket support *(note that Telnet and RLogin are plain text protocols and thus insecure)*

- File transfers via FTP, SFTP, Gopher, and HTTP/HTTPS

- Config-file driven configuration

- Submenu "skip menu navigation" - select options in multiple nested menus at once

- Automatic menu screen generation and resizing

- Emulated slow baud rate support

- Electronic mail (SMTP, POP3, IMAP4)

- Newsgroups (NNTP)

- Native realtime chat

- Internet Relay Chat client and server, with native IRC and Discord relays

- TDD/TTY (telecommunications device for the deaf) support

- Sysop capabilities
  - Node spying
  - Kick nodes

## Donations

LBBS is developed entirely by volunteers on their own time.

If LBBS is useful to you, please [consider donating](https://interlinked.us/donate) to fund further development and features. Thank you!

## Usage

### Installation

To install LBBS, you will need to compile it from source. Fortunately, we've made this as easy as possible:

```
cd /usr/src
git clone https://github.com/InterLinked1/lbbs.git
cd lbbs
./install_prereq.sh
make
make install
make samples
```

To start the BBS with the sysop console in the foreground, you can then run `lbbs -c`. To daemonize it, just run `lbbs`.

At the console, press `?` or `h` for a list of available commands. You can also run `lbbs -?` or `lbbs -h` for a list of startup options.

Some configuration of the BBS will be needed before you can use it. Consult the sample configs in `/etc/lbbs` for an overview of settings you may need to configure. At a minimum, you will need to add a menu to the BBS (`menus.conf`).

LBBS is best run on a modern version of Debian Linux (Debian 10 or Debian 11). Note that LBBS likely is not currently portable to non-Linux systems, e.g. BSD or UNIX. It likely won't be a lot of work to make it more portable, but that work hasn't been done yet since I only test and run BBSes on Linux. Additionally, LBBS requires gcc to compile, since it uses some gcc-specific compiler extensions.

**WARNING: Do not run the BBS as root!** Create a non-root user and configure the BBS to run as that instead. See `lbbs -?` or `/etc/lbbs/bbs.conf` to configure the run user and run group.

### Sysoping

Sysops can monitor and control the BBS using the sysop console provided by the `mod_sysop` module. For example, you can list information about configured BBS menus, spy on nodes, or restart the entire BBS. Most commands are available by typing `/` followed by a string, although some common commands are available by single-press hotkeys. Press `?` in the console for a list of available options and commands.

If the BBS is started in the foreground, a sysop console is available on STDIN/STDOUT.

Additionally, regardless of how the BBS is started, the sysop console can be accessed remotely (so called since the access originates from outside the BBS process) by running the `rsysop` program. This program is part of the external utilities and is installed to `/var/lib/lbbs/external/rsysop`.

**WARNING:** Note that anyone that can access the `rsysop` program is able to perform sysop tasks on the BBS. Even if the BBS is not running as root, it should be running under an account that is secured to the sysop.

### Configuration

Configuration of LBBS and modules are done entirely through INI config files. Different parts of LBBS have their own config files, as does each module that uses one.

Config files go in `/etc/lbbs` and are as follows:

- `bbs.conf` - key startup settings

- `door_irc.conf` - IRC clients

- `mail.conf` - Email configuration

- `menus.conf` - BBS menus, menu items and options. **This is the heart of LBBS configuration.**

- `mod_auth_mysql.conf` - MySQL/MariaDB auth provider module config

- `mod_auth_static.conf` - Static user configuration (intended for development and testing)

- `mod_chanserv.conf` - ChanServ IRC service config

- `mod_discord.conf` - Discord/IRC relay configuration

- `mod_mail.conf ` - General email server configuration

- `mod_relay_irc.conf` - IRC/IRC relay configuration

- `modules.conf` - module loading settings (to disable a module, you do it here)

- `net_finger.conf` - Finger protocol config

- `net_ftp.conf` - FTP (File Transfer Protocol) server config

- `net_gopher.conf` - Gopher server config

- `net_http.conf` - HTTP/HTTPS web server config

- `net_imap.conf` - IMAP4 server config

- `net_irc.conf` - Internet Relay Chat server config

- `net_nntp.conf` - Network News Transfer Protocol (NNTP) server config

- `net_pop3.conf` - POP3 server config

- `net_rlogin`.conf` - RLogin server configuration

- `net_smtp.conf` - SMTP server configuration

- `net_ssh.conf` - SSH and SFTP server configuration

- `net_telnet.conf` - Telnet server configuration

- `nodes.conf` - Node-related configuration

- `tls.conf` - SSL/TLS configuration

- `transfers.conf` - File transfer configuration

- `variables.conf` - Global variable configuration

Each sample config file documents all available options. Refer to the sample configs for more info about a file.

### Network Login Services / Comm Drivers

Network login or comm drivers are modules in the `nets` source directory, responsible for implementing a network login service. These are what allow users to actually connect to the BBS itself.

Generally speaking, the comm drivers implement some kind of standardized TCP-based protocol. There are builtin drivers for Telnet, RLogin, and SSH. **Note that Telnet and RLogin are plain text protocols and thus insecure!** Using SSH is recommended for any public connections.

LBBS also includes a UNIX domain socket module (`net_unix`). One use case for this is if you want to "proxy" connections to the BBS through the main, public-facing network login service. For example, say you run OpenSSH on port 22 (and you don't want to change the port), but you still want people to be able to connect to your BBS on port 22. You can create a public user account on your server that executes the BBS as a program, rather than providing a login shell. If you do this, you don't need any of the network drivers loaded or running besides `net_unix` (UNIX domain sockets provide the least overhead for these kinds of loopback connections). That said, the UNIX domain socket driver is quite primitive. Using one of the other drivers, particularly the SSH driver, will provide a far superior experience.

Do note, should you choose to proxy connections in th emanner described above, there are several important security implications of doing this that you *must* understand, or you open your system up to vulnerabilities. See the comments at the top of the source file `nets/net_unix.c`

Unless you really know what you are doing, you are probably better off using LBBS's builtin network login services, rather than proxying the connection through your system's primary network login services. This will provide a more seamless user experience and mitigate potential security vulnerabilities described above.

Each comm driver handles window resizing in its own way.

- `net_ssh` - full support for window size at login and resizing later

- `net_telnet` - support for window size at login, but currently no support for resizing later (could be added as an enhancement)

- `net_rlogin` - broken support for window size at login (doesn't work)

- `net_unix` - no support for window size. UNIX domain sockets are similar to a raw TCP socket, there is no terminal protocol riding on top of the socket here. If you need (or want) window size support, use a different network comm driver.

None of the network comm drivers are mutually exclusive - you can enable as many or few as you want, and users can use whatever protocol they want to.

Generally speaking, for the reasons listed above, SSH is the recommended protocol. Apart from being the only protocol secure to use over the Internet, it also fully handles terminal resizing.

The BBS also comes with some network services that aren't intended for terminal usage, e.g.:

- `net_finger` - Finger server

- `net_ftp` - File Transfer Protocol server

- `net_gopher` - Gopher server

- `net_http` - HTTP/HTTPS web server

- `net_imap` - IMAP server

- `net_irc` - Internet Relay Chat server

- `net_nntp` - Network News Transfer Protocol (NNTP) server

- `net_pop3` - POP3 server

- `net_smtp` - Simple Mail Transfer Protocol (SMTP) server

- `net_sftp` - Secure File Transfer Protocol server

### Using mod_auth_mysql

The BBS needs at least one authentication provider to be able to authenticate users.
`mod_auth_mysql` is an included module that authenticates users against a MySQL/MariaDB database.

You'll need to create a user for the database, if you haven't already:

```
CREATE USER 'bbs'@'localhost' IDENTIFIED BY 'P@ssw0rdUShouldChAngE!';
GRANT ALL PRIVILEGES ON bbs.* TO 'bbs'@'localhost';
FLUSH PRIVILEGES;
```

Then, create a database called `bbs` and a table called `users` - the SQL to do so is in `scripts/dbcreate.sql`.

Don't forget to also add your DB connection info to `mod_auth_mysql.conf`!

## Licensing

If you intend to run an LBBS system or make modifications to LBBS, you must understand the license.

LBBS is licensed under the [GNU General Public License version 2 (GPLv2)](https://choosealicense.com/licenses/gpl-2.0/). At a high level, GPLv2 is a copyleft license (sometimes referred to as a more restrictive license) that requires that any modifications to the source code be distributed to any users to whom the resulting program is made available. This contrasts with more permissive licenses such as the Apache License or MIT License that do not have such requirements. See the link for more details.

There are a few reasons I opted to license LBBS under the GPL, some out of choice, others less so:

- The reality is that the days of commercial BBSes are long over. There is no money in running a BBS these days, nor is there any money in writing BBS software. LBBS is no exception. The majority of BBS users, sysops, and developers are all hobbyists doing this for fun, not to make a living. A copyleft license better suits the environment of BBSes today, encouraging contributors to share modifications and improvements with the community.

- I considered licensing the LBBS core under the Affero General Public License (AGPL) and modules under the GPL, since BBS users are not entitled to the source code under the GPL unless the binaries are distributed to them. However, it was (and is) important to me that modules not be licensed under the AGPL, but something more permissive such as the GPL, so that sysops and developers could create their own custom modules and not be required to disclose the source code to their users, in order to provide more freedom for users and sysops. Rather than complicating things with split-licensing, licensing everything under the more permissive GPL is simpler.

- Parts of the LBBS source code and binary have dependencies on components that are themselves licensed under the GPL. For example, the history functionality for the sysop command line, which depends on `history(3)`, a component of the GNU readline library (licensed under the GPL). So, LBBS is required to be licensed with a copyleft license at least as strong as the GPL.

Note that these are merely the rationales for licensing this project under GPLv2, but the vast majority of users and sysops do not need to be concerned about the license, unless you intend to distribute compiled versions of LBBS or make modifications to it. If you make modifications to the source and distribute the result, you must make the source code available under a license at least as restrictive as the GPLv2. If you are merely using LBBS or are a sysop running LBBS, then there is nothing special you need to do to comply with the GPL. Obviously, this is not legal advice, and you should consult a lawyer if you have licensing questions or concerns.

## Development Notes

### Architecture

LBBS is a single-process multithreaded program. The BBS "core" is the `lbbs` binary comprised of all the source files in the `bbs` directory. The core is designed to be small, with additional functionality provided by modules that can be dynamically loaded and unloaded as desired. This makes it easy for functionality to be added in a self-contained manner.

For example, the sysop console is provided by the `mod_sysop` module. It is not built in to the core. This makes it easy to modify the sysop console, and you could even write your own sysop console and use that instead!

This approach is also relied on for key functionality that could be implemented in different ways. For example, the `mod_auth_mysql` is an *authentication provider* that can process user login requests, backed by a MySQL/MariaDB database. However, maybe you use a PostgreSQL database instead, or SQLite, or some other kind of authentication mechanism entirely. LBBS doesn't dictate that users be stored in a certain type of file on disk, or even locally at all. Since auth providers can use any DBMS, API, etc. you could easily set up a BBS server fleet, all sharing the same users. The point is authentication is handled in a very flexible manner. (Obviously, somebody will need to write a module to handle authentication the way you want to, but this can be done without touching the BBS core at all.)

At a high level, incoming connections are accepted by a network comm driver using a socket. The connection is accepted and each network driver does its own preliminary handling of the connection, such as getting the terminal size. Then, a thread is spawned to handle the node and a pseudoterminal (PTY) is created, with the master side connected to the socket file descriptor and the slave side used for all node I/O. For example, to put the terminal in non-canonical mode or enable/disable echo, these operations are performed on the slave side of the node's PTY.

Some network drivers, such as `net_ssh` currently create a pseudoterminal internally, such that the master end of the SSH pseudoterminal is connected to the libssh file descriptor, and the slave side is used as the node's master PTY fd (as opposed to the socket fd directly).

LBBS does not use ncurses to draw to the screen, partly for simplicity, and partly because ncurses is not multithread safe. While it is possible to compile ncurses such that it has support for threading, this version is not highly portable or often used, and even the maintainer of ncurses discourages using it. Instead, menus are generally generated dynamically directly by LBBS, based on the node's terminal dimensions, although sysops may also manually create menus that are displayed instead.

Menus are the heart of the BBS and where a lot of the action is, both for users and from an architecture perspective. After a user logs in, the BBS node is dropped into the menu routines which handle all the work of generating and displaying menus and options, reading options from users, and taking the appropriate action, such as executing a program, another module, or displaying a submenu.

### Directory Structure

Most code is documented using doxygen, and each source file describes its purpose. The LBBS source is organized into several key directories:

- `bbs` - Source files that comprise the main `lbbs` binary. This is the "BBS core".

- `configs` - Sample config files for LBBS modules and settings

- `doors` - Door modules (both internal and external doors). In BBSing, the concept of a "door" refers to an interface between the BBS and an external application, used to access games, utilities, and other functionality not part of the BBS program itself. In LBBS, door modules are actually BBS modules, but they are not part of the BBS core, so are external in that sense only. Door modules can call LBBS functions, however, and run within the BBS process, so LBBS door modules offer enhanced functionality beyond that provided with a raw door. To execute a true external program, use `exec` rather than `door` in `menus.conf`.

- `external` - External programs that are not part of the BBS itself, but may be useful supplements or programs to use in conjunction with it. For example, these can be executed as external programs from within the BBS, but they could also be run on their own.

- `include` - Header files for core files

- `modules` - General modules

- `nets` - Network login services / communication driver modules

- `scripts` - Useful scripts for use with LBBS

- `terms` - Reserved for possible future terminal modules, not yet used

LBBS, once installed, uses several system directories:

- `/etc/lbbs/` - config files

- `/usr/sbin/lbbs` - LBBS binary

- `/usr/lib/lbbs/modules/` - shared object modules

- `/var/lib/lbbs/` - General LBBS resources

  - `/var/lib/lbbs/external` - External programs
  - `/var/lib/lbbs/scripts` - Useful scripts for use with LBBS

- `/var/log/lbbs/` - log directory

### Make Targets

You can compile and link all the files in a directory containing source files simply by specifying the directory, e.g.:

- `make bbs`

- `make doors`

- `make modules`

- `make nets`

To compile everything, run `make all`, or simply `make`.

To install the LBBS binary, all shared object modules, and all external programs, run `make install`.

To create the config directory with sample configuration files, run `make samples`.

To delete all compiled code to ensure all source code is cleanly recompiled, run `make clean`.

Some targets are also included to aid developers in debugging the BBS or sysops in tracking down bugs. You will need valgrind installed (`apt-get install valgrind`):

- `make valgrind` - Run valgrind and log all results to `valgrind.txt`. If you suspect a memory leak, you must attach this file when opening an issue.

- `make valgrindsupp` - Generate suppression list from valgrind findings. You should not do this without a good understanding of the findings from the previous step.

- `make valgrindfd` - Run valgrind but show findings in the foreground, rather than redirecting them to a log file.

- `make helgrind` - Run helgrind in the foreground. This is useful for debugging locking.

Most stuff is commented for doxygen. You can generate the doxygen docs by running `make doxygen` (you may need to run `apt-get install -y doxygen graphviz` first)

### Debugging

LBBS includes a number of builtin tools to assist with debugging, in addition to using `valgrind` as described above. You can turn on debugging by using the `-d` option on startup (up to 10 `d`'s), setting a debug level in `bbs.conf`, or changing the debug level at runtime using the `/debug` command. **If you submit an issue, you must provide full debug (`debug=10`)**.

From the sysop console, you can run `/threads` to show running threads, helpful if you suspect threading-related issues. Running `/fds` will show all open file descriptors.

LBBS includes unit tests for functionality that can be tested individually. These can be run using `/runtests` from the sysop console.

**Dumper Script**

The `/var/lib/lbbs/scripts/bbs_dumper.sh` script can be helpful when trying to get backtraces of LBBS.

Usage:

- `./bbs_dumper.sh pid` - Get PID of running BBS process

- `./bbs_dumper.sh term` - Terminate running BBS process (SIGKILL)

- `./bbs_dumper.sh term` - Quit running BBS process (SIGQUIT)

- `./bbs_dumper.sh postdump` - Obtain a backtrace from a core dump file

- `./bbs_dumper.sh livedump` - Obtain a backtrace from a currently running LBBS process

### A Note About ABI (Application Binary Interface) Compatibility

Some projects strive to preserve ABI as much as possible when making changes (e.g. no breaking ABI changes allowed within a major revision).

While it is certainly not an objective to break ABI, it should be preferred to break ABI if necessary when making changes (e.g. adding
arguments to a function) when doing it a different way would result in less maintainable or clunkier code in the long run.

For example, if the original function is still useful, it can still call the new function under the hood (which would preserve ABI), but if not,
the original prototype should simply be expanded.

Likewise, when adding members to a struct (which can break ABI if not placed at the end), members should be added at the most logical place,
not necessarily at the end.

In essence, changes will not strive to preserve ABI if that is the sole purpose of making a change a particular way.

The implication of this development philosophy is that users *should **not** expect* any ABI compatibility between versions from different points in time.
Mixing files from different source revisions may result in an unstable system. You should always fully recompile LBBS from source when building
a new or updated version.

### Coding Guidelines

Please follow the coding guidelines used in this repository. They are by and large K&R C, importantly:

- Use tabs, not spaces.

- Indent properly. Functions (only) should have the opening brace on their own line.

- Braces denoting code blocks are always required, even for single-statement if, for, while, etc. where the braces are technically optional.

- Use `/* multi-line C89 */` comments only, not `// single-line C99 comments`.

- Trim all trailing whitespace.

- All public functions (anything in header files) should be documented using doxygen.

- Add unit tests if possible (modules only).

- Avoid C functions that are not multi-thread safe.

- If there is a BBS function to do something, use it. (e.g. use the `bbs_pthread_create` wrapper, not `pthread_create` directly).

- All source files should use UNIX line endings (LF). However, config files should use DOS/Windows line endings (CR LF). This is so that if Windows users open a config file in an old version of Notepad, it displays properly.
