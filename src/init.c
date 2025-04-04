/*
This file is part of mktorrent
Copyright (C) 2007, 2009 Emil Renner Berthing

mktorrent is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

mktorrent is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
*/


#include <stdlib.h>       /* exit() */
#include <sys/types.h>    /* off_t */
#include <errno.h>        /* errno */
#include <string.h>       /* strerror() */
#include <stdio.h>        /* perror(), printf() etc. */
#include <sys/stat.h>     /* the stat structure */
#include <unistd.h>       /* getopt(), getcwd(), sysconf() */
#include <string.h>       /* strcmp(), strlen(), strncpy() */
#include <strings.h>      /* strcasecmp() */
#include <inttypes.h>     /* PRId64 etc. */
#include <getopt.h>       /* getopt_long() */
#include <unistd.h>       /* getopt(), optarg, optind */
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>

#include "export.h"
#include "mktorrent.h"
#include "ftw.h"
#include "msg.h"
#include "ll.h"

/* Forward declarations */
EXPORT void cleanup_metafile(struct metafile *m);

#ifndef MAX_OPENFD
#define MAX_OPENFD 100	/* Maximum number of file descriptors
			   file_tree_walk() will open */
#endif


static void strip_ending_dirseps(char *s)
{
	char *end = s;

	if (!s) return;  /* Guard against NULL pointer */

	while (*end)
		end++;

	while (end > s && *(--end) == DIRSEP_CHAR)
		*end = '\0';
}

static const char *basename(const char *s)
{
	const char *r = s;

	if (!s) return "";  /* Guard against NULL pointer */

	while (*s != '\0') {
		if (*s == DIRSEP_CHAR)
			r = ++s;
		else
			++s;
	}

	return r;
}

static void set_absolute_file_path(struct metafile *m)
{
	/* if the file_path is already an absolute path just
	   return that */
	if (m->metainfo_file_path && *m->metainfo_file_path == DIRSEP_CHAR) {
		/* we need to reallocate the string, because we want to be able to
		 * free() it in cleanup_metafile(), and that would not be possible
		 * if m->metainfo_file_path pointed to a string from argv[]
		 */
		m->metainfo_file_path = strdup(m->metainfo_file_path);
		FATAL_IF0(m->metainfo_file_path == NULL, "out of memory\n");
		return;
	}

	char cwd[PATH_MAX]; /* Buffer for current working directory */
	size_t cwd_len;
	size_t result_len;
	char *result;

	/* Get the current working directory */
	if (getcwd(cwd, PATH_MAX) == NULL) {
		fatal("getcwd failed: %s\n", strerror(errno));
	}
	
	cwd_len = strlen(cwd);

	/* Calculate the required final string length once to avoid multiple reallocations */
	if (m->metainfo_file_path == NULL) {
		/* Need space for: cwd + '/' + torrent_name + '.torrent' + '\0' */
		result_len = cwd_len + 1 + strlen(m->torrent_name) + 8 + 1;
	} else {
		/* Need space for: cwd + '/' + metainfo_file_path + '\0' */
		result_len = cwd_len + 1 + strlen(m->metainfo_file_path) + 1;
	}

	/* Allocate the final string once with the exact size needed */
	result = malloc(result_len);
	FATAL_IF0(result == NULL, "out of memory\n");

	/* First copy the current working directory */
	memcpy(result, cwd, cwd_len);
	
	/* Then add the appropriate suffix */
	if (m->metainfo_file_path == NULL) {
		sprintf(result + cwd_len, DIRSEP "%s.torrent", m->torrent_name);
	} else {
		sprintf(result + cwd_len, DIRSEP "%s", m->metainfo_file_path);
	}

	m->metainfo_file_path = result;
}

/*
 * Check if a URL is valid
 * Returns 1 for valid URLs, 0 for invalid ones
 * Note: This is used directly by validate_url_list now
 */
static int is_valid_url(const char *url) __attribute__((unused));
static int is_valid_url(const char *url)
{
	/* Quick validation checks */
	if (!url || !*url) 
		return 0;

	/* Use direct pointer comparison for protocols to avoid multiple strncmp calls */
	const char *domain = NULL;
	size_t domain_offset = 0;
	
	if (strncmp(url, "http://", 7) == 0) {
		domain_offset = 7;
	} else if (strncmp(url, "https://", 8) == 0) {
		domain_offset = 8;
	} else if (strncmp(url, "udp://", 6) == 0) {
		domain_offset = 6;
	} else {
		return 0; /* Invalid protocol */
	}
	
	domain = url + domain_offset;
	
	/* Empty domain check */
	if (!*domain)
		return 0;
	
	/* Find dot in domain without using strchr for better performance */
	const char *dot = domain;
	while (*dot && *dot != '.')
		dot++;
	
	/* Must have a dot and at least one character after it */
	return (*dot == '.' && dot[1] != '\0');
}

/*
 * Split comma-separated string into a linked list
 * validate_url: no longer used, kept for backward compatibility
 * Errors:
 * [ 37%] Building C object CMakeFiles/mktorrent.dir/src/init.c.o
 * /home/thomas/Dev/GitHub/Organizations/MediaEase/binary_repos/old/mktorrent/src/init.c: In function 'get_slist':
 * /home/thomas/Dev/GitHub/Organizations/MediaEase/binary_repos/old/mktorrent/src/init.c:187:42: warning: unused parameter 'validate_url' [-Wunused-parameter]
 * /187 | static struct ll *get_slist(char *s, int validate_url)
 * |                                      ~~~~^~~~~~~~~~~~
 * [ 50%] Building C object CMakeFiles/mktorrent.dir/src/ll.c.o
 */
static struct ll *get_slist(char *s, int validate_url)
{
	/* Mark validate_url as unused to prevent compiler warning */
	(void)validate_url;
	
	/* Validate input */
	if (!s) {
		fprintf(stderr, "Error: NULL string passed to get_slist\n");
		return NULL;
	}

	/* allocate a new list */
	struct ll *list = ll_new();
	if (!list) {
		fprintf(stderr, "Error: Failed to create new list in get_slist\n");
		return NULL;
	}

	/* Fast path for empty string */
	if (!*s)
		return list;

	char *start = s;
	char *e;

	/* Process entire string in one pass */
	while (1) {
		/* Find next comma or end of string */
		e = strchr(start, ',');
		
		/* If we have a non-empty element, add it */
		if (!e) {
			/* Last element */
			if (*start && ll_append(list, start, 0) == NULL) {
				fprintf(stderr, "Error: Failed to append to list in get_slist\n");
				ll_free(list, NULL);
				return NULL;
			}
			break;
		}
		
		/* Set comma to null terminator temporarily */
		*e = '\0';
		
		/* Only add non-empty elements */
		if (start != e && ll_append(list, start, 0) == NULL) {
			fprintf(stderr, "Error: Failed to append to list in get_slist\n");
			/* Restore comma before free */
			*e = ',';
			ll_free(list, NULL);
			return NULL;
		}
		
		/* Restore comma */
		*e = ',';
		
		/* Move to next element */
		start = e + 1;
	}

	return list;
}

/*
 * checks if target is a directory
 * sets the file_list and size if it isn't
 */
static int is_dir(struct metafile *m, char *target)
{
	struct stat s;		/* stat structure for stat() to fill */

	if (!target || !*target) {
		fprintf(stderr, "Error: Empty target path\n");
		return -1;
	}

	/* stat the target */
	if (stat(target, &s) == -1) {
		fprintf(stderr, "Cannot stat '%s': %s\n", target, strerror(errno));
		return -1;
	}

	/* if it is a directory, just return 1 */
	if (S_ISDIR(s.st_mode))
		return 1;

	/* if it isn't a regular file either, something is wrong.. */
	if (!S_ISREG(s.st_mode)) {
		fprintf(stderr, "'%s' is neither a directory nor regular file\n", target);
		return -1;
	}

	/* if it has negative size, something it wrong */
	if (s.st_size < 0) {
		fprintf(stderr, "'%s' has negative size\n", target);
		return -1;
	}

	/* since we know the torrent is just a single file and we've
	   already stat'ed it, we might as well set the file list */
	char *path_copy = strdup(target);
	if (!path_copy) {
		fprintf(stderr, "Error: Out of memory when duplicating path\n");
		return -1;
	}

	struct file_data fd = {
		path_copy,
		(uintmax_t) s.st_size
	};

	if (ll_append(m->file_list, &fd, sizeof(fd)) == NULL) {
		fprintf(stderr, "Error: Out of memory when appending to file list\n");
		free(path_copy);
		return -1;
	}

	/* ..and size variable */
	m->size = (uintmax_t) s.st_size;

	/* now return 0 since it isn't a directory */
	return 0;
}

/*
 * called by file_tree_walk() on every file and directory in the subtree
 * counts the number of (readable) files, their commulative size and adds
 * their names and individual sizes to the file list
 */
static int process_node(const char *path, const struct stat *sb, void *data)
{
	struct metafile *m = data;

	/* skip non-regular files */
	if (!S_ISREG(sb->st_mode))
		return 0;

	/* ignore the leading "./" */
	path += 2;

	/* now path should be readable otherwise
	 * display a warning and skip it */
	if (access(path, R_OK)) {
		fprintf(stderr, "warning: cannot read '%s', skipping\n", path);
		return 0;
	}

	if (sb->st_size < 0) {
		fprintf(stderr, "warning: '%s' has negative size, skipping\n", path);
		return 0;
	}

	if (m->verbose)
		printf("adding %s\n", path);

	/* count the total size of the files */
	m->size += (uintmax_t) sb->st_size;

	/* create a new file list node for the file */
	struct file_data fd = {
		strdup(path),
		(uintmax_t) sb->st_size
	};

	if (fd.path == NULL || ll_append(m->file_list, &fd, sizeof(fd)) == NULL) {
		fprintf(stderr, "fatal error: out of memory\n");
		return -1;
	}

	return 0;
}

/*
 * 'elp!
 */
static void print_help()
{
	printf(
	  "Usage: mktorrent [OPTIONS] <target directory or filename>\n\n"
	  "Options:\n"
#ifdef USE_LONG_OPTIONS
	  "-a, --announce=<url>[,<url>]* : specify the full announce URLs\n"
	  "                                additional -a adds backup trackers\n"
	  "-c, --comment=<comment>       : add a comment to the metainfo\n"
	  "-d, --no-date                 : don't write the creation date\n"
	  "-D, --no-created-by 			 : don't write the creating software name and version\n"
	  "-e, --exclude=<pat>[,<pat>]*  : exclude files whose name matches the pattern <pat>\n"
	  "                                see the man page glob(7)\n"
	  "-f, --force                   : overwrite output file if it exists\n"
	  "-h, --help                    : show this help screen\n"
	  "-l, --piece-length=<n>        : set the piece length to 2^n bytes,\n"
	  "                                default is calculated from the total size\n"
	  "-n, --name=<name>             : set the name of the torrent\n"
	  "                                default is the basename of the target\n"
	  "-o, --output=<filename>       : set the path and filename of the created file\n"
	  "                                default is <name>.torrent\n"
	  "-p, --private                 : set the private flag\n"
	  "-s, --source=<source>         : add source string embedded in infohash\n"
#ifdef USE_PTHREADS
	  "-t, --threads=<n>             : use <n> threads for calculating hashes\n"
	  "                                default is the number of CPU cores\n"
#endif
	  "-v, --verbose                 : be verbose\n"
	  "-w, --web-seed=<url>[,<url>]* : add web seed URLs\n"
	  "                                additional -w adds more URLs\n"
	  "-x, --cross-seed              : ensure info hash is unique for easier cross-seeding\n"
#else
	  "-a <url>[,<url>]* : specify the full announce URLs\n"
	  "                    additional -a adds backup trackers\n"
	  "-c <comment>      : add a comment to the metainfo\n"
	  "-d                : don't write the creation date\n"
	  "-e <pat>[,<pat>]* : exclude files whose name matches the pattern <pat>\n"
	  "                    see the man page glob(7)\n"
	  "-f                : overwrite output file if it exists\n"
	  "-h                : show this help screen\n"
	  "-l <n>            : set the piece length to 2^n bytes,\n"
	  "                    default is calculated from the total size\n"
	  "-n <name>         : set the name of the torrent,\n"
	  "                    default is the basename of the target\n"
	  "-o <filename>     : set the path and filename of the created file\n"
	  "                    default is <name>.torrent\n"
	  "-p                : set the private flag\n"
	  "-s                : add source string embedded in infohash\n"
#ifdef USE_PTHREADS
	  "-t <n>            : use <n> threads for calculating hashes\n"
	  "                    default is the number of CPU cores\n"
#endif
	  "-v                : be verbose\n"
	  "-w <url>[,<url>]* : add web seed URLs\n"
	  "                    additional -w adds more URLs\n"
	  "-x                : ensure info hash is unique for easier cross-seeding\n"
#endif
	  "\nPlease send bug reports, patches, feature requests, praise and\n"
	  "general gossip about the program to: mktorrent@rudde.org\n");
}

/*
 * print the full announce list
 */
static void print_announce_list(struct ll *list)
{
	unsigned int tier = 1;

	LL_FOR(node, list) {

		struct ll *inner_list = LL_DATA(node);

		printf("    %u : %s\n",
			tier, LL_DATA_AS(LL_HEAD(inner_list), const char*));

		LL_FOR_FROM(inner_node, LL_NEXT(LL_HEAD(inner_list))) {
			printf("        %s\n", LL_DATA_AS(inner_node, const char*));
		}

		tier += 1;
	}
}

/*
 * print the list of web seed URLs
 */
static void print_web_seed_list(struct ll *list)
{
	printf("  Web Seed URL: ");

	if (LL_IS_EMPTY(list)) {
		printf("none\n");
		return;
	}

	printf("%s\n", LL_DATA_AS(LL_HEAD(list), const char*));
	LL_FOR_FROM(node, LL_NEXT(LL_HEAD(list))) {
		printf("                %s\n", LL_DATA_AS(node, const char*));
	}
}

/*
 * print out all the options
 */
static void dump_options(struct metafile *m)
{
	printf("Options:\n"
	       "  Announce URLs:\n");

	print_announce_list(m->announce_list);

	printf("  Torrent name: %s\n"
	       "  Metafile:     %s\n"
	       "  Piece length: %u\n"
#ifdef USE_PTHREADS
	       "  Threads:      %ld\n"
#endif
	       "  Be verbose:   yes\n",
	       m->torrent_name, m->metainfo_file_path, m->piece_length
#ifdef USE_PTHREADS
	       ,m->threads
#endif
	       );

	printf("  Write date:   ");
	if (m->no_creation_date)
		printf("no\n");
	else
		printf("yes\n");
	
	printf("  Write created_by:   ");
	if (m->no_created_by)
		printf("no\n");
	else
		printf("yes\n");

	print_web_seed_list(m->web_seed_list);

	/* Print source string only if set */
	if (m->source)
		printf("\n Source:      %s\n\n", m->source);

	printf("  Comment:      ");
	if (m->comment == NULL)
		printf("none\n\n");
	else
		printf("\"%s\"\n\n", m->comment);
}

static int file_data_cmp_by_name(const void *a, const void *b)
{
	const struct file_data *x = a, *y = b;
	return strcmp(x->path, y->path);
}

static void file_data_clear(void *data)
{
	struct file_data *fd = data;
	free(fd->path);
}

static void free_inner_list(void *data)
{
	struct ll *list = data;
	ll_free(list, NULL);
}

/*
 * Validates a comma-separated list of URLs
 * Returns 1 if all URLs are valid, 0 if any are invalid
 */
static int validate_url_list(const char *url_list)
{
	/* Handle NULL input */
	if (!url_list) {
		fprintf(stderr, "Error: NULL URL list\n");
		return 0;
	}
	
	const char *url_start = url_list;
	const char *url_end;
	int valid = 1;
	
	/* Process URLs in place without making a copy */
	while (*url_start) {
		/* Skip leading commas and spaces */
		while (*url_start == ',' || *url_start == ' ')
			url_start++;
			
		/* End of string */
		if (!*url_start)
			break;
			
		/* Find the end of this URL (next comma or end of string) */
		url_end = url_start;
		while (*url_end && *url_end != ',')
			url_end++;
			
		/* Empty URL segment */
		if (url_end == url_start) {
			url_start = url_end;
			if (*url_start)
				url_start++;
			continue;
		}
		
		/* Check protocol prefix without duplicating memory */
		if ((url_end - url_start >= 7 && strncmp(url_start, "http://", 7) == 0) ||
		    (url_end - url_start >= 8 && strncmp(url_start, "https://", 8) == 0) ||
		    (url_end - url_start >= 6 && strncmp(url_start, "udp://", 6) == 0)) {
			
			/* Find domain start */
			const char *domain;
			if (strncmp(url_start, "http://", 7) == 0)
				domain = url_start + 7;
			else if (strncmp(url_start, "https://", 8) == 0)
				domain = url_start + 8;
			else
				domain = url_start + 6;
				
			/* Find dot in domain */
			const char *dot = domain;
			while (dot < url_end && *dot != '.')
				dot++;
				
			/* Validate domain format */
			if (dot == domain || dot >= url_end - 1) {
				fprintf(stderr, "Error: Invalid URL format\n");
				valid = 0;
				break;
			}
		} else {
			fprintf(stderr, "Error: Invalid URL protocol\n");
			valid = 0;
			break;
		}
		
		/* Move to next URL */
		url_start = url_end;
		if (*url_start)
			url_start++;
	}
	
	return valid;
}

/*
 * parse and check the command line options given
 * and fill out the appropriate fields of the
 * metafile structure
 */
EXPORT int init(struct metafile *m, int argc, char *argv[])
{
	int c;			/* return value of getopt() */
	const uintmax_t piece_len_maxes[] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		(uintmax_t) BIT15MAX * ONEMEG, (uintmax_t) BIT16MAX * ONEMEG,
		(uintmax_t) BIT17MAX * ONEMEG, (uintmax_t) BIT18MAX * ONEMEG,
		(uintmax_t) BIT19MAX * ONEMEG, (uintmax_t) BIT20MAX * ONEMEG,
		(uintmax_t) BIT21MAX * ONEMEG, (uintmax_t) BIT22MAX * ONEMEG,
		(uintmax_t) BIT23MAX * ONEMEG
	};

	const int num_piece_len_maxes = sizeof(piece_len_maxes) /
	    sizeof(piece_len_maxes[0]);

#ifdef USE_LONG_OPTIONS
	/* the option structure to pass to getopt_long() */
	static struct option long_options[] = {
		{"announce", 1, NULL, 'a'},
		{"comment", 1, NULL, 'c'},
		{"no-date", 0, NULL, 'd'},
		{"no-created-by", 0, NULL, 'D'},
		{"exclude", 1, NULL, 'e'},
		{"force", 0, NULL, 'f'},
		{"help", 0, NULL, 'h'},
		{"piece-length", 1, NULL, 'l'},
		{"name", 1, NULL, 'n'},
		{"output", 1, NULL, 'o'},
		{"private", 0, NULL, 'p'},
		{"source", 1, NULL, 's'},
#ifdef USE_PTHREADS
		{"threads", 1, NULL, 't'},
#endif
		{"verbose", 0, NULL, 'v'},
		{"web-seed", 1, NULL, 'w'},
		{"cross-seed", 0, NULL, 'x'},
		{NULL, 0, NULL, 0}
	};
#endif

	m->announce_list = ll_new();
	FATAL_IF0(m->announce_list == NULL, "out of memory\n");

	m->web_seed_list = ll_new();
	FATAL_IF0(m->web_seed_list == NULL, "out of memory\n");

	m->file_list = ll_new();
	FATAL_IF0(m->file_list == NULL, "out of memory\n");

	m->exclude_list = ll_new();
	FATAL_IF0(m->exclude_list == NULL, "out of memory\n");

	/* now parse the command line options */
#ifdef USE_PTHREADS
#define OPT_STRING "a:c:e:dDfhl:n:o:ps:t:vw:x"
#else
#define OPT_STRING "a:c:e:dDfhl:n:o:ps:vw:x"
#endif
#ifdef USE_LONG_OPTIONS
	while ((c = getopt_long(argc, argv, OPT_STRING,
				long_options, NULL)) != -1) {
#else
	while ((c = getopt(argc, argv, OPT_STRING)) != -1) {
#endif
#undef OPT_STRING
		switch (c) {
		case 'a':
			if (m->announce_list == NULL) {
				m->announce_list = ll_new();
				FATAL_IF0(m->announce_list == NULL, "out of memory\n");
			}

			/* Check if URL list is valid before trying to add it */
			if (!validate_url_list(optarg)) {
				/* Error message already printed by validate_url_list */
				return -1;
			}
			
			struct ll *url_list = get_slist(optarg, 0);
			if (url_list == NULL || ll_append(m->announce_list, url_list, 0) == NULL) {
				fprintf(stderr, "Error: failed to add announce URL to list\n");
				if (url_list) ll_free(url_list, NULL);
				return -1;
			}
			break;
		case 'c':
			/* Set comment */
			if (m->comment) {
				free(m->comment);  /* Free any previous comment */
			}
			m->comment = strdup(optarg);
			FATAL_IF0(m->comment == NULL, "out of memory\n");
			break;
		case 'd':
			m->no_creation_date = 1;
			break;
		case 'D':
			m->no_created_by = 1;
			break;
		case 'e':
			ll_extend(m->exclude_list, get_slist(optarg, 0));
			break;
		case 'f':
			m->force_overwrite = 1;
			break;
		case 'h':
			print_help();
			return EXIT_SUCCESS;
		case 'l':
			m->piece_length = atoi(optarg);
			break;
		case 'n':
			m->torrent_name = optarg;
			break;
		case 'o':
			m->metainfo_file_path = optarg;
			break;
		case 'p':
			m->private = 1;
			break;
		case 's':
			m->source = optarg;
			break;
#ifdef USE_PTHREADS
		case 't':
			m->threads = atoi(optarg);
			break;
#endif
		case 'v':
			m->verbose = 1;
			break;
		case 'w':
			/* Validate web seed URL list first */
			if (!validate_url_list(optarg)) {
				/* Error message already printed by validate_url_list */
				return -1;
			}
			
			struct ll *web_seed_list = get_slist(optarg, 0);
			if (web_seed_list == NULL) {
				fprintf(stderr, "Error: failed to add web seed URL to list\n");
				return -1;
			}
			ll_extend(m->web_seed_list, web_seed_list);
			break;
		case 'x':
			m->cross_seed = 1;
			break;
		case '?':
			fatal("use -h for help.\n");
		}
	}

	/* check that the user provided a file or directory from which to create the torrent */
	FATAL_IF0(optind >= argc,
		"must specify the contents, use -h for help\n");

#ifdef USE_PTHREADS
	/* check the number of threads */
	if (m->threads) {
		FATAL_IF0(m->threads > 20,
			"the number of threads is limited to at most 20\n");
	} else {
#ifdef _SC_NPROCESSORS_ONLN
		m->threads = sysconf(_SC_NPROCESSORS_ONLN);
		if (m->threads <= 0)
#endif
			m->threads = 2; /* some sane default */
	}
#endif

	/* strip ending DIRSEP's from target */
	strip_ending_dirseps(argv[optind]);

	/* if the torrent name isn't set use the basename of the target */
	if (m->torrent_name == NULL)
		m->torrent_name = basename(argv[optind]);

	/* if we still don't have a torrent name, default to "unnamed" */
	if (m->torrent_name == NULL || *m->torrent_name == '\0') {
		m->torrent_name = "unnamed";
	}

	/* make sure m->metainfo_file_path is the absolute path to the file */
	set_absolute_file_path(m);

	/* if we should be verbose print out all the options
	   as we have set them */
	if (m->verbose)
		dump_options(m);

	/* check if target is a directory or just a single file */
	m->target_is_directory = is_dir(m, argv[optind]);
	if (m->target_is_directory) {
		/* change to the specified directory */
		FATAL_IF(chdir(argv[optind]), "cannot change directory to '%s': %s\n",
			argv[optind], strerror(errno));

		if (file_tree_walk("." DIRSEP, MAX_OPENFD, process_node, m))
			return EXIT_FAILURE;
	}

	ll_sort(m->file_list, file_data_cmp_by_name);

	/* determine the piece length based on the torrent size if
	   it was not user specified. */
	if (m->piece_length == 0) {
		int i;
		for (i = 15; i < num_piece_len_maxes &&
			m->piece_length == 0; i++)
			if (m->size <= piece_len_maxes[i])
				m->piece_length = i;
		if (m->piece_length == 0)
			m->piece_length = num_piece_len_maxes;
	} else {
		/* if user did specify a piece length, verify its validity */
		FATAL_IF0(m->piece_length < 15 || m->piece_length > 28,
			"the piece length must be a number between 15 and 28.\n");
	}

	/* convert the piece length from power of 2 to an integer. */
	m->piece_length = 1 << m->piece_length;

	/* calculate the number of pieces
	   pieces = ceil( size / piece_length ) */
	m->pieces = (m->size + m->piece_length - 1) / m->piece_length;

	/* now print the size and piece count if we should be verbose */
	if (m->verbose)
		printf("\n%" PRIuMAX " bytes in all\n"
			"that's %u pieces of %u bytes each\n\n",
			m->size, m->pieces, m->piece_length);

	/* check if we have anything to hash */
	if (argc < optind + 1) {
		fprintf(stderr, "Error: no input file or directory specified\n");
		print_help();
		return -1;
	}

	return 0;
}

EXPORT void cleanup_metafile(struct metafile *m)
{
	ll_free(m->announce_list, free_inner_list);

	ll_free(m->file_list, file_data_clear);

	ll_free(m->web_seed_list, NULL);

	ll_free(m->exclude_list, NULL);

	free(m->metainfo_file_path);
}
