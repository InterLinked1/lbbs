/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Module Build Management (modman, for short)
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h> /* use open */
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>

#include <sys/stat.h>

/*! \note
 * This program is somewhat inspired, at least conceptually, by Asterisk's "menuselect".
 * However, this program is a lot simpler. We do not (currently) allow users to toggle
 * on/off various modules to build. This is a reasonable thing to want, but considering
 * how much smaller this source tree is than Asterisk's, it's not the end of the world
 * if we build everything, regardless of what the user will use.
 *
 * More relevant, however, is that many modules have external library dependencies
 * that are unlikely to be met, unless the user has run scripts/install_prereq.sh.
 * However, the user may not want to install all the prereqs, for the simple reason
 * that the user may not need the modules that require them.
 *
 * Another use case is doing a fresh install of the BBS on a new system.
 * If only the BBS core and a particular module is needed, it's unnecessary
 * to build everything else.
 *
 * To make the build process easier, our primary objective is to make it easy to automatically
 * disable modules that will fail to build successfully due to unmet dependencies.
 *
 * Of course, this program itself, to be effective, has no external dependencies,
 * and is fairly minimal.
 */

static int debug_level = 0;

#define COLOR_GREEN "\x1b[32m"
#define COLOR_RED "\x1b[31m"
#define COLOR_RESET "\x1b[0m"

#define modman_log(level, fmt, ...) \
	if (debug_level >= level) { \
		fprintf(stderr, fmt, ## __VA_ARGS__); \
	}

#define modman_warning(fmt, ...) fprintf(stderr, " ********** " COLOR_RED "WARNING: " COLOR_RESET fmt, ## __VA_ARGS__)
#define modman_error(fmt, ...) fprintf(stderr, " ********** " COLOR_RED "ERROR: " COLOR_RESET fmt, ## __VA_ARGS__)

#define TERMINATE_AT(buf, c) { \
	char *__term_at = strchr(buf, c); \
	if (__term_at) *__term_at = '\0'; \
}

static int create_file(const char *filename)
{
	int fd;

	fd = open(filename, O_APPEND | O_CREAT, 0644);
	if (fd < 0) {
		modman_error("Failed to open/create file %s: %s\n", filename, strerror(errno));
		return -1;
	}
	/* Just create an empty file and exit */
	close(fd);
	modman_log(2, "     ---- Created dummy target '%s'\n", filename);
	return 0;
}

#define IS_SAFE_CHAR(c) (isalnum(c) || c == ' ' || c == '-' || c == '_' || c == '.')

/*! \brief Resolve a Makefile variable that executes a shell command */
static int resolve_makefile_varcmd(const char *restrict dirname, const char *restrict varname, char *restrict libbuf, size_t len)
{
	FILE *fp;
	char filename[512];
	char buf[1024];
	char cmd[512];
	char *tmp;
	int res = 1;
	size_t varnamelen;

	/* Open the Makefile a second time, for another pass to try to resolve this variable */
	snprintf(filename, sizeof(filename), "%s/%s", dirname, "Makefile");
	fp = fopen(filename, "r");
	if (!fp) {
		modman_error("Failed to open %s: %s\n", filename, strerror(errno));
		return -1;
	}

	varnamelen = strlen(varname);
	while ((fgets(buf, sizeof(buf), fp))) {
		FILE *pfp;
		if (strncmp(buf, varname, varnamelen)) {
			continue;
		}
		modman_log(8, "  Found Makefile variable '%s'\n", varname);
		tmp = strstr(buf, "shell ");
		if (!tmp) {
			/* Not a shell execution */
			break;
		}
		tmp += strlen("shell ");
		if (!*tmp) {
			modman_error("Empty shell execution?\n");
			break;
		}
		/* Ditch the trailing parenthesis for the command, and then execute it and see what it returns */
		snprintf(cmd, sizeof(cmd), "%s", tmp);
		TERMINATE_AT(cmd, ')');

		/* Hopefully there's nothing nasty in the Makefile... do some basic validation to avoid shell injection */
		tmp = cmd;
		while (*tmp) {
			if (!IS_SAFE_CHAR(*tmp)) {
				modman_warning("Shell command '%s' contains disallowed character '%c'\n", cmd, *tmp);
				fclose(fp);
				return -1;
			}
			tmp++;
		}

		pfp = popen(cmd, "r");
		if (!pfp) {
			modman_error("popen(%s) failed: %s\n", cmd, strerror(errno));
			break;
		}
		if (fgets(libbuf, len, pfp)) {
			TERMINATE_AT(libbuf, '\n');
			modman_log(6, "  Resolved Makefile variable '%s' => '%s'\n", varname, libbuf);
			res = 0;
		}
		pclose(pfp);
		/* We found the variable, no need to search further lines */
		break;
	}

	fclose(fp);
	return res;
}

/*!
 * \brief Check if a library dependency is met
 * \retval 1 if missing dependency, 0 otherwise
 */
static int check_lib(const char *modname, const char *libname)
{
	char cmd[256];
	int res;
	const char *colorfmt;
	const char *s;

	/* Skip the actual -l */
	libname += 2;
	if (!*libname) {
		/* Empty linking dependency ? */
		modman_error("Empty linker command?\n");
		return 0;
	}
	/* Check if this library exists on the system */
	/* This is a lazy way to check, but it's reliable since
	 * there are multiple directories that need to be considered.
	 * This isn't particularly performant, but this is a build tool,
	 * not the actual program, so it doesn't really matter much.
	 *
	 * Just make sure there's nothing funny going on with the name,
	 * to avoid shell injection. */
	s = libname;
	while (*s) {
		if (!IS_SAFE_CHAR(*s)) {
			modman_error("Unexpected character '%c' in library name 'lib%s'\n", *s, libname);
			break;
		}
		s++;
	}
	if (*s) {
		/* If we didn't reach the end, we hit an invalid character */
		return 0;
	}
	snprintf(cmd, sizeof(cmd), "ldconfig -p | grep 'lib%s.so' 2>/dev/null 1>&2", libname);
	res = system(cmd);
	/* ldconfig | grep returned nonzero, which means
	 * we couldn't find any libraries by that name. */
	if (res && res != 256) {
		modman_error("Unexpected system return for 'lib%s' %d: %s\n", libname, res, strerror(errno));
		return 0;
	}

	colorfmt = res ? COLOR_RED : COLOR_GREEN;
	modman_log(0, "   == Module '%s' is dependent on library 'lib%s' ==> %s%s%s\n", modname, libname, colorfmt, res == 256 ? "MISSING" : "FOUND", COLOR_RESET);
	if (res) {
		return 1; /* Missing dep */
	}
	return 0;
}

/*! \brief Check if all library dependencies are met */
static int check_libs(const char *dirname, const char *modname, char *restrict buf)
{
	char *libname, *token;
	int missing_deps = 0;

	/* We're parsing a module.
	 * Look for special linking dependencies. */
	modman_log(7, "Processing module '%s'\n", modname);

	/* We've found a library. In fact, we could have found a multiple.
	 * We assume that all the library names are provided explicitly
	 * (rather than using Makefile variables).
	 * Process any token that starts with -l */
	token = buf;
	while ((libname = strsep(&token, " "))) {
		/* Remove any embedded newline */
		TERMINATE_AT(libname, '\n');
		if (strncmp(libname, "-l", 2)) {
			/* We do not support Makefile variables, but we do need to support
			 * shell command execution of pkg-config, for robustness.
			 * If the variable contains "_LIBS", assume that's what this is
			 * and try to emulate expansion of it, to get the library name. */
			if (!strncmp(libname, "$(", 2) && strstr(libname, "_LIBS)")) {
				char lib_buf[256] = "";
				/* Strip the surrounding $() */
				libname += 2;
				TERMINATE_AT(libname, ')');
				if (resolve_makefile_varcmd(dirname, libname, lib_buf, sizeof(lib_buf)) != -1) {
					char *lib, *libs = lib_buf;
					/* If the command returned successfully but the output is empty,
					 * that means we could NOT successfully run the command.
					 * This can happen if it's a lib-specific command, e.g. mysql_config
					 * instead of pkg-config.
					 * In this case, we know the lib is not installed, so also count as failure. */
					if (!*libs) {
						modman_log(0, "   == Module '%s' is dependent on a library that cannot be resolved ==> %s%s%s\n", modname, COLOR_RED, "UNRESOLVED", COLOR_RESET);
						missing_deps++;
					} else {
						while ((lib = strsep(&libs, " "))) {
							if (strlen(lib) > 0) {
								if (strncmp(lib, "-l", 2)) {
									continue; /* Not a lib flag */
								}
								missing_deps += check_lib(modname, lib);
							}
						}
					}
				}
			} else {
				continue;
			}
		} else {
			missing_deps += check_lib(modname, libname);
		}
	}
	return missing_deps;
}

static char sys_include_paths[2048] = ""; /* Buffer to cache system header file locations */
static int loaded_header_files = 0;

static int load_header_file_locations(void)
{
	FILE *pfp;
	char buf[512];
	char *pos = sys_include_paths;
	size_t len = sizeof(sys_include_paths);

	/* This is the same every time we call this function,
	 * so it's wasteful to do it for EVERY header file, but,
	 * performance is not of the essence in this program. */
	pfp = popen("gcc -v -E a.c 2>&1", "r"); /* All output is on stderr by default */
	if (!pfp) {
		modman_error("popen(%s) failed: %s\n", "gcc -v -E a.c", strerror(errno));
		return -1;
	}
	while (len > 0 && fgets(buf, sizeof(buf), pfp)) {
		int bytes;
		if (strncmp(buf, " /", 2)) {
			continue;
		}
		if (strchr(buf + 1, ' ')) {
			continue;
		}
		modman_log(7, "  System include path: %s", buf + 1); /* Already ends in LF */
		bytes = snprintf(pos, len, "%s", buf + 1);
		pos += bytes;
		len -= bytes;
	}
	pclose(pfp);
	return 0;
}

#define STANDARD_LIB_HEADER(f) if (!strcmp(filename, f)) return 1;

static inline int is_standard_lib_header(const char *filename)
{
	/* As long as libc is present, these standard header files are canonical */

	/* C89 headers */
	STANDARD_LIB_HEADER("assert.h");
	STANDARD_LIB_HEADER("ctype.h");
	STANDARD_LIB_HEADER("errno.h");
	STANDARD_LIB_HEADER("float.h");
	STANDARD_LIB_HEADER("limits.h");
	STANDARD_LIB_HEADER("locale.h");
	STANDARD_LIB_HEADER("math.h");
	STANDARD_LIB_HEADER("setjmp.h");
	STANDARD_LIB_HEADER("signal.h");
	STANDARD_LIB_HEADER("stdarg.h");
	STANDARD_LIB_HEADER("stddef.h");
	STANDARD_LIB_HEADER("stdio.h");
	STANDARD_LIB_HEADER("stdlib.h");
	STANDARD_LIB_HEADER("string.h");
	STANDARD_LIB_HEADER("time.h");

	/* Small, select subset of other POSIX headers */
	STANDARD_LIB_HEADER("dirent.h");
	STANDARD_LIB_HEADER("fcntl.h");
	STANDARD_LIB_HEADER("poll.h");
	STANDARD_LIB_HEADER("pthread.h");
	STANDARD_LIB_HEADER("sys/stat.h"); /* modman itself uses sys/stat.h, so it'd be ironic not to include it here, as it's obviously present if we got built. */
	STANDARD_LIB_HEADER("unistd.h");

	return 0;
}

/*!
 * \brief Check if a header file exists in any of the system include paths
 * \retval -1 if error, 0 if doesn't exist, 1 if exists
 */
static int check_header_file(const char *dirname, const char *modname, const char *incfile, FILE *mfp, int *restrict metdeps)
{
	char incpaths[sizeof(sys_include_paths)];
	int exists = 0;
	char *path, *paths = incpaths;
	int num_incpaths = 0;
	char filename[1024];
	int common_include_file = 0;

	modman_log(7, "  Checking existence of system header file '%s'\n", incfile);
	if (!loaded_header_files) {
		if (load_header_file_locations()) {
			modman_error("Can't check existence of system header files\n");
			return -1;
		}
		loaded_header_files = 1;
	}

	strcpy(incpaths, sys_include_paths); /* Safe */
	paths = incpaths;
	while ((path = strsep(&paths, "\n"))) {
		char *includedir;

		includedir = strchr(path, '/'); /* Skip leading whitespace, and strchr cannot return NULL. */
		TERMINATE_AT(path, '\n');
		num_incpaths++;

		snprintf(filename, sizeof(filename), "%s/%s", includedir, incfile);
		modman_log(8, "  Checking existence of %s\n", filename);
		if (!access(filename, R_OK)) {
			exists = 1;
			common_include_file = is_standard_lib_header(incfile);
			break;
		}
	}
	if (!exists) {
		char objname[512];
		char buf[1024];
		size_t objnamelen;
		int in_obj = 0;
		/* If we still couldn't find it,
		 * check if the .o target for this module has custom flags through pkg-config.
		 * e.g. mod_mimeparse
		 */
		rewind(mfp);
		snprintf(objname, sizeof(objname), "%s", modname);
		TERMINATE_AT(objname, '.');
		strncat(objname, ".o", sizeof(objname));
		objnamelen = strlen(objname);
		while (fgets(buf, sizeof(buf), mfp)) {
			char *token, *tokens;
			if (!in_obj) {
				if (!strncmp(buf, objname, objnamelen)) {
					in_obj = 1;
				}
				continue;
			}
			if (!strstr(buf, "-fPIC")) {
				continue;
			}
			/* Found it. Check each token. */
			tokens = buf;
			while ((token = strsep(&tokens, " "))) {
				char inc_path[256] = "";
				if (strncmp(token, "$(", 2)) {
					continue;
				}
				/* Found a variable. Expand it. First, strip the surrounding $() */
				token += 2;
				TERMINATE_AT(token, ')');
				if (resolve_makefile_varcmd(dirname, token, inc_path, sizeof(inc_path)) != -1) {
					if (*inc_path) {
						tokens = inc_path;
						while ((token = strsep(&tokens, " "))) {
							if (strncmp(token, "-I", 2)) {
								continue; /* Not an include path */
							}
							token += 2;
							if (!*token) {
								continue;
							}
							snprintf(filename, sizeof(filename), "%s/%s", token, incfile);
							modman_log(8, "  Checking existence of %s\n", filename);
							if (!access(filename, R_OK)) {
								exists = 1;
								break;
							}
						}
					}
				}
			}
		}
	}
	if (exists) {
		int loglevel = common_include_file ? 6 : 0; /* If this is a common library file, don't display it unless debug level is high. */
		if (debug_level >= loglevel) {
			(*metdeps)++;
		}
		modman_log(loglevel, "   == Module '%s' includes system header file '%s' => %s%s%s\n", modname, incfile, COLOR_GREEN, "FOUND", COLOR_RESET);
	} else {
		modman_log(0, "   == Module '%s' includes system header file '%s' => %s%s%s\n", modname, incfile, COLOR_RED, "MISSING", COLOR_RESET);
	}
	return exists;
}

/*! \brief Check if all system header files in a source file exist */
static int check_headers(const char *dirname, const char *modname, FILE *mfp, int *restrict met_deps)
{
	FILE *fp;
	char filename[515];
	char buf[1024];
	int unmet_headers = 0;

	snprintf(filename, sizeof(filename), "%s/%s", dirname, modname);
	TERMINATE_AT(filename, '.');
	strncat(filename, ".c", sizeof(filename));

	fp = fopen(filename, "r");
	if (!fp) {
		modman_error("Failed to open %s: %s\n", filename, strerror(errno));
		return 0;
	}

	while ((fgets(buf, sizeof(buf), fp))) {
		char *incfile;
		/* Check for system include files */
		if (strncmp(buf, "#include <", 10)) {
			continue;
		}
		incfile = buf + 10;
		if (!*incfile) {
			continue;
		}
		TERMINATE_AT(incfile, '>');
		if (!check_header_file(dirname, modname, incfile, mfp, met_deps)) {
			unmet_headers++;
		}
	}

	fclose(fp);
	return unmet_headers;
}

static int check_module(const char *dirname, const char *modname, FILE *mfp, int autodisable)
{
	char *tmp;
	char buf[1024];
	char filename[1024];
	char src_filename[1024];
	int missing_deps = 0;
	size_t modnamelen;
	int in_module = 0;
	int has_deps = 0;
	int metdeps = 0;

	/* Find the dependencies in the Makefile */
	rewind(mfp);
	modnamelen = strlen(modname);
	while ((fgets(buf, sizeof(buf), mfp))) {
		if (!in_module) {
			if (!strncmp(buf, modname, modnamelen)) {
				in_module = 1;
			}
			continue;
		}

		/* The line we're looking for in the Makefile has this */
		if (!strstr(buf, "-shared")) {
			continue;
		}

		/* Check for missing libraries */
		has_deps = 1;
		missing_deps += check_libs(dirname, modname, buf);
		break;
	}

	/* Check for missing header files.
	 * This accounts for modules that depend on a module that has a direct library dependency,
	 * but do not directly link to it and just use the library header files.
	 * Example: mod_auth_mysql only uses the mysql header files,
	 * but does not link to any external libraries itself (mod_mysql, upon which it depends, however, does).
	 *
	 * Strictly speaking, if missing_deps is already positive at this point, we don't need to do this part,
	 * since we already know the module is missing dependencies. However, do it for completeness.
	 */
	missing_deps += check_headers(dirname, modname, mfp, &metdeps);
	has_deps += missing_deps;
	has_deps += metdeps;

	/* Just because the make target exists, doesn't mean the source file for the module does.
	 * For example, someone may have manually deleted it.
	 * In that case, there's no point in creating dummy targets, and we should just ignore this target. */
	snprintf(src_filename, sizeof(src_filename), "%s/%s", dirname, modname);
	tmp = strchr(src_filename, '.');
	/* tmp must exist since filename must end in .so, unless truncation occured */
	if (!tmp) {
		modman_error("Source filename '%s' does not have file extension?\n", src_filename);
		return -1;
	}
	tmp++;
	if (!*tmp) {
		modman_error("Source filename '%s' has empty file extension?\n", src_filename);
		return -1;
	}
	*tmp++ = 'c';
	*tmp = '\0';

	/* This is kind of a crude hack, but it works and is simple.
	 * To ensure that this module does not get built,  create dummy targets that will cause make to skip
	 * processing this module.
	 * This is better than just deleting these modules from the source tree,
	 * in case the dependencies are later met; the user can then build them,
	 * without having to refetch these source files.
	 * When doing "make install", we then ensure that we DELETE all zero-size .so files from the modules lib dir.
	 *
	 * It would be a bit cleaner to create a "nobuild" file like modulename.nobuild,
	 * and skip compiling the .so/.o files if that file exists, but since a lot of
	 * targets are duplicated if they need to have libraries added, this would be a
	 * lot of logic duplicated floating around, with the current Makefile target structure.
	 *
	 * So this is a bit of a silly method, but it's simple and it works.
	 */
	snprintf(filename, sizeof(filename), "%s/%s", dirname, modname);

	if (!missing_deps) {
		/* All dependencies satisfied, hooray */
		if (autodisable) {
			/* Delete dummy files if they exist, for some reason */
			if (!access(filename, R_OK)) {
				struct stat st;
				if (stat(filename, &st)) {
					modman_error("Failed to stat %s: %s\n", filename, strerror(errno));
				} else {
					long size = st.st_size;
					if (size == 0) {
						int errs = 0;
						if (unlink(filename)) {
							modman_error("Failed to remove dummy zero-size file '%s': %s\n", filename, strerror(errno));
							errs++;
						}
						/* Repeat for the .d */
						TERMINATE_AT(filename, '.');
						strncat(filename, ".c", sizeof(filename) - 1);
						if (unlink(filename)) {
							modman_error("Failed to remove dummy zero-size file '%s': %s\n", filename, strerror(errno));
							errs++;
						}
						if (!errs) {
							modman_log(0, "    ---> Re-enabled module '%s', now that dependencies are met\n", modname);
						}
					}
				}
			}
		}
		if (!has_deps) {
			/* Only show this message if we haven't already displayed a log message for this module to the user */
			modman_log(0, "   == Module '%s' has no unmet dependencies => %s%s%s\n", modname, COLOR_GREEN, "OKAY", COLOR_RESET);
		}
		return 0;
	}

	if (access(src_filename, R_OK)) {
		modman_log(0, "    -- Source file '%s' is missing, nothing to do\n", src_filename);
		return 0;
	}

	/* If any required libraries are missing, autodisable, if asked to */
	if (autodisable) {
		/* If the compiled module already exists, for some reason,
		 * then that's really strange... */
		if (!access(filename, R_OK)) {
			struct stat st;
			/* If the file exists, there are two real possibilities:
			 * 1) It's a dummy zero-size file, which we created earlier. Perfectly okay, ignore.
			 * 2) It's the actual built shared object module, which is odd since
			 *    dependencies aren't satisfied, so the header files are probably missing,
			 *    which would have caused compilation failure. But there's a possibility
			 *    that the header files are present even though the library is missing.
			 *    We should probably warn the user about this...
			 */
			if (stat(filename, &st)) {
				modman_error("Failed to stat %s: %s\n", filename, strerror(errno));
			} else {
				long size = st.st_size;
				if (size > 0) {
					modman_warning("Compiled module '%s' is present, even though required libraries are not installed\n", filename);
				} else {
					modman_log(0, "    ---> Module '%s' is already disabled\n", modname);
				}
			}
			return 0;
		}

		modman_log(0, "    ---> Autodisabling module '%s'\n", modname);

		if (create_file(filename)) {
			return 0;
		}

		/* It's not necessary to create dummy .o files, since the .so are the main target.
		 * As long as that is satisfied, then we're good. */

		/* Now, do the same for the .d file (in addition to the .so file).
		 * Rather than making another snprintf call, we can just modify the last part of the filename.
		 * We confirm at the beginning of the outer loop that .so is present in the module name, so this CANNOT fail,
		 * unless snprintf truncation occured for some reason. */
		tmp = strchr(filename, '.');
		if (!tmp) {
			modman_error("Object filename '%s' does not have file extension?\n", filename);
			return -1;
		}
		tmp++;
		if (!*tmp) {
			modman_error("Object filename '%s' has empty file extension?\n", filename);
			return -1;
		}
		/* This is the s in .so. Change it to o and terminate, for .d */
		*tmp++ = 'd';
		*tmp = '\0';
		if (create_file(filename)) {
			return -1;
		}
	}
	return 0;
}

static int check_module_subdir(const char *subdir, int autodisable)
{
	struct dirent *entry, **entries;
	int numfiles, fno = 0;
	char makefile[128];
	FILE *fp;

	/* Use scandir instead of opendir, for ordered sort */
	numfiles = scandir(subdir, &entries, NULL, alphasort);
	if (numfiles < 0) {
		modman_error("Directory '%s' could not be opened: %s\n", subdir, strerror(errno));
		return -1;
	}

	/* Try to parse the Makefile for library dependencies.
	 * At the moment, any dependencies of modules are hardcoded into the Makefiles,
	 * so there's no need to traverse the entire directory for libraries, since files that
	 * aren't explicitly in the Makefile don't have special build dependencies,
	 * but modules do need to be traversed explicitly to check for header dependencies. */
	snprintf(makefile, sizeof(makefile), "%s/%s", subdir, "Makefile");
	fp = fopen(makefile, "r");
	if (!fp) {
		modman_error("File '%s' could not be opened: %s\n", subdir, strerror(errno));
		while (fno < numfiles && (entry = entries[fno++])) {
			free(entry);
		}
		free(entries);
		return -1;
	}

	while (fno < numfiles && (entry = entries[fno++])) {
		char modname[512];

		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			free(entry);
			continue;
		}
		/* Look for all the .c files */
		if (!strstr(entry->d_name, ".c")) {
			free(entry);
			continue;
		}
		/* Found a module source file. Check it */
		snprintf(modname, sizeof(modname), "%s", entry->d_name);
		TERMINATE_AT(modname, '.');
		strncat(modname, ".so", sizeof(modname) - 1);
		check_module(subdir, modname, fp, autodisable);
		free(entry);
	}

	free(entries);
	fclose(fp);
	return 0;
}

static int check_unmet_dependencies(int autodisable)
{
	int res = 0;

	/* We are assumed to be running from the BBS source directory root.
	 * If this is not the case, bail now. */

	if (access("bbs", R_OK) || access("Makefile", R_OK)) {
		modman_error("This program must be run from the LBBS root source directory.\n");
		return -1;
	}

#if 0
	res |= check_module_subdir("bbs", 0); /* Check the core, too, but never autodisable, the build should fail if we the core dependencies aren't met */
#endif
	res |= check_module_subdir("doors", autodisable);
	res |= check_module_subdir("io", autodisable);
	res |= check_module_subdir("modules", autodisable);
	res |= check_module_subdir("nets", autodisable);

	return res;
}

static void show_help(void)
{
	printf("modman - LBBS Module Build Management\n");
	printf(" -d           Check all module dependencies and automatically disable modules with unmet dependencies\n");
	printf(" -h           Show this help\n");
	printf(" -t           List all module dependencies and their status, but make no changes\n");
	printf(" -v           Increase verbose/debug level\n");
	printf("(C) 2024 Naveen Albert\n");
}

int main(int argc, char *argv[])
{
	char c;
	static const char *getopt_settings = "?dhtv";

	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		switch (c) {
		case '?':
		case 'h':
			show_help();
			return 0;
		case 'v':
			debug_level++;
			break;
		default:
			break;
		}
	}

	optind = 0;
	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		switch (c) {
		case '?':
		case 'h':
			show_help();
			return 0;
		case 'd':
			check_unmet_dependencies(1);
			return 0;
		case 't':
			check_unmet_dependencies(0);
			return 0;
		default:
			modman_error("Invalid option: %c\n", c);
			return -1;
		}
	}

	return 0;
}
