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


#include <sys/types.h>    /* off_t */
#include <stdio.h>        /* fprintf() etc. */
#include <string.h>       /* strlen() etc. */
#include <time.h>         /* time() */
#include <inttypes.h>     /* PRIuMAX */
#include <stdlib.h>       /* random() */

#ifdef USE_OPENSSL
#include <openssl/sha.h>  /* SHA_DIGEST_LENGTH */
#else
#include "sha1.h"
#endif

#include "export.h"       /* EXPORT */
#include "mktorrent.h"    /* struct metafile */
#include "output.h"

/* Length of random data for cross-seeding */
#define CROSS_SEED_RAND_LENGTH 16

/*
 * write announce list
 * Returns 0 on success, -1 on error
 */
static int write_announce_list(FILE *f, struct ll *list)
{
	int err;

	/* the announce list is a list of lists of urls */
	err = fprintf(f, "13:announce-listl");
	if (err < 0) {
		fprintf(stderr, "Error writing announce-list start\n");
		return -1;
	}

	/* go through them all.. */
	LL_FOR(tier_node, list) {
		/* .. and print the lists */
		err = fprintf(f, "l");
		if (err < 0) {
			fprintf(stderr, "Error writing tier list start\n");
			return -1;
		}

		LL_FOR(announce_url_node, LL_DATA_AS(tier_node, struct ll*)) {
			const char *announce_url =
				LL_DATA_AS(announce_url_node, const char*);

			err = fprintf(f, "%lu:%s",
					(unsigned long) strlen(announce_url), announce_url);
			if (err < 0) {
				fprintf(stderr, "Error writing announce URL\n");
				return -1;
			}
		}

		err = fprintf(f, "e");
		if (err < 0) {
			fprintf(stderr, "Error writing tier list end\n");
			return -1;
		}
	}
	
	err = fprintf(f, "e");
	if (err < 0) {
		fprintf(stderr, "Error writing announce-list end\n");
		return -1;
	}
	
	return 0;
}

/*
 * write file list
 * Returns 0 on success, -1 on error
 */
static int write_file_list(FILE *f, struct ll *list)
{
	char *a, *b;
	int err;

	err = fprintf(f, "5:filesl");
	if (err < 0) {
		fprintf(stderr, "Error writing files list start\n");
		return -1;
	}

	/* go through all the files */
	LL_FOR(file_node, list) {
		struct file_data *fd = LL_DATA_AS(file_node, struct file_data*);

		/* the file list contains a dictionary for every file
		   with entries for the length and path
		   write the length first */
		err = fprintf(f, "d6:lengthi%" PRIuMAX "e4:pathl", fd->size);
		if (err < 0) {
			fprintf(stderr, "Error writing file entry\n");
			return -1;
		}
		
		/* the file path is written as a list of subdirectories
		   and the last entry is the filename
		   sorry this code is even uglier than the rest */
		a = fd->path;
		/* while there are subdirectories before the filename.. */
		while ((b = strchr(a, DIRSEP_CHAR)) != NULL) {
			/* set the next DIRSEP_CHAR to '\0' so fprintf
			   will only write the first subdirectory name */
			*b = '\0';
			/* print it bencoded */
			err = fprintf(f, "%lu:%s", b - a, a);
			if (err < 0) {
				/* restore the path before returning */
				*b = DIRSEP_CHAR;
				fprintf(stderr, "Error writing directory name\n");
				return -1;
			}
			/* undo our alteration to the string */
			*b = DIRSEP_CHAR;
			/* and move a to the beginning of the next
			   subdir or filename */
			a = b + 1;
		}
		/* now print the filename bencoded and end the
		   path name list and file dictionary */
		err = fprintf(f, "%lu:%see", (unsigned long)strlen(a), a);
		if (err < 0) {
			fprintf(stderr, "Error writing filename\n");
			return -1;
		}
	}

	/* whew, now end the file list */
	err = fprintf(f, "e");
	if (err < 0) {
		fprintf(stderr, "Error writing files list end\n");
		return -1;
	}
	
	return 0;
}

/*
 * write web seed list
 * Returns 0 on success, -1 on error
 */
static int write_web_seed_list(FILE *f, struct ll *list)
{
	int err;
	
	/* print the entry and start the list */
	err = fprintf(f, "8:url-listl");
	if (err < 0) {
		fprintf(stderr, "Error writing url-list start\n");
		return -1;
	}
	
	/* go through the list and write each URL */
	LL_FOR(node, list) {
		const char *web_seed_url = LL_DATA_AS(node, const char*);
		err = fprintf(f, "%lu:%s",
			(unsigned long) strlen(web_seed_url), web_seed_url);
		if (err < 0) {
			fprintf(stderr, "Error writing web seed URL\n");
			return -1;
		}
	}
	
	/* end the list */
	err = fprintf(f, "e");
	if (err < 0) {
		fprintf(stderr, "Error writing url-list end\n");
		return -1;
	}
	
	return 0;
}

/*
 * Generate random data for cross-seeding
 * Returns 0 on success, -1 on error
 */
static int write_cross_seed_data(FILE *f)
{
	int i;
	int err;
	
	err = fprintf(f, "12:x_cross_seed%u:mktorrent-", CROSS_SEED_RAND_LENGTH * 2 + 10);
	if (err < 0) {
		fprintf(stderr, "Error writing cross-seed field\n");
		return -1;
	}
	
	for (i = 0; i < CROSS_SEED_RAND_LENGTH; i++) {
		unsigned char rand_byte = random();
		if (fputc("0123456789ABCDEF"[rand_byte >> 4], f) == EOF) {
			fprintf(stderr, "Error writing cross-seed data\n");
			return -1;
		}
		if (fputc("0123456789ABCDEF"[rand_byte & 0x0F], f) == EOF) {
			fprintf(stderr, "Error writing cross-seed data\n");
			return -1;
		}
	}
	
	return 0;
}

/*
 * write metainfo to the file stream using all the information
 * we've gathered so far and the hash string calculated
 */
EXPORT int write_metainfo(FILE *f, struct metafile *m, unsigned char *hash_string)
{
	int err;

	/* let the user know we've started writing the metainfo file */
	printf("writing metainfo file... ");
	fflush(stdout);

	/* every metainfo file is one big dictonary */
	err = fprintf(f, "d");
	if (err < 0) {
		fprintf(stderr, "Error writing dictionary start\n");
		return -1;
	}

	if (!LL_IS_EMPTY(m->announce_list)) {
		struct ll *first_tier =
			LL_DATA_AS(LL_HEAD(m->announce_list), struct ll*);

		/* write the announce URL */
		const char *first_announce_url
			= LL_DATA_AS(LL_HEAD(first_tier), const char*);

		err = fprintf(f, "8:announce%lu:%s",
			(unsigned long) strlen(first_announce_url), first_announce_url);
		if (err < 0) {
			fprintf(stderr, "Error writing announce URL\n");
			return -1;
		}

		/* write the announce-list entry if we have
		 * more than one announce URL, namely
		 * a) there are at least two tiers, or      (first part of OR)
		 * b) there are at least two URLs in tier 1 (second part of OR)
		 */
		if (LL_NEXT(LL_HEAD(m->announce_list)) || LL_NEXT(LL_HEAD(first_tier))) {
			if (write_announce_list(f, m->announce_list) != 0) {
				return -1;
			}
		}
	}

	/* add the comment if one is specified */
	if (m->comment != NULL) {
		err = fprintf(f, "7:comment%lu:%s",
				(unsigned long)strlen(m->comment),
				m->comment);
		if (err < 0) {
			fprintf(stderr, "Error writing comment\n");
			return -1;
		}
	}

#ifndef VERSION
#define VERSION "1.1"
#endif
    char const *const created_by = "mktorrent " VERSION;
	if (!m->no_created_by) {
		err = fprintf(f, "10:created by%zu:%s", strlen(created_by), created_by);
		if (err < 0) {
			fprintf(stderr, "Error writing created by\n");
			return -1;
		}
	}

	/* add the creation date */
	if (!m->no_creation_date) {
		err = fprintf(f, "13:creation datei%lde",
			(long)time(NULL));
		if (err < 0) {
			fprintf(stderr, "Error writing creation date\n");
			return -1;
		}
	}

	/* now here comes the info section
	   it is yet another dictionary */
	err = fprintf(f, "4:infod");
	if (err < 0) {
		fprintf(stderr, "Error writing info dictionary start\n");
		return -1;
	}

	/* first entry is either 'length', which specifies the length of a
	   single file torrent, or a list of files and their respective sizes */
	if (!m->target_is_directory) {
		err = fprintf(f, "6:lengthi%" PRIuMAX "e",
			LL_DATA_AS(LL_HEAD(m->file_list), struct file_data*)->size);
		if (err < 0) {
			fprintf(stderr, "Error writing single file length\n");
			return -1;
		}
	} else {
		if (write_file_list(f, m->file_list) != 0) {
			return -1;
		}
	}

	/* add cross-seed data if requested */
	if (m->cross_seed) {
		if (write_cross_seed_data(f) != 0) {
			return -1;
		}
	}

	/* the info section also contains the name of the torrent,
	   the piece length and the hash string */
	err = fprintf(f, "4:name%lu:%s12:piece lengthi%ue6:pieces%u:",
		(unsigned long)strlen(m->torrent_name), m->torrent_name,
		m->piece_length, m->pieces * SHA_DIGEST_LENGTH);
	if (err < 0) {
		fprintf(stderr, "Error writing torrent name and piece data\n");
		return -1;
	}

	/* write the hash data */
	if (fwrite(hash_string, 1, m->pieces * SHA_DIGEST_LENGTH, f)
			!= m->pieces * SHA_DIGEST_LENGTH) {
		fprintf(stderr, "Error writing piece hashes\n");
		return -1;
	}

	/* set the private flag */
	if (m->private) {
		err = fprintf(f, "7:privatei1e");
		if (err < 0) {
			fprintf(stderr, "Error writing private flag\n");
			return -1;
		}
	}

	/* add source if specified */
	if (m->source) {
		err = fprintf(f, "6:source%lu:%s",
			(unsigned long) strlen(m->source), m->source);
		if (err < 0) {
			fprintf(stderr, "Error writing source\n");
			return -1;
		}
	}

	/* end the info section */
	err = fprintf(f, "e");
	if (err < 0) {
		fprintf(stderr, "Error ending info dictionary\n");
		return -1;
	}

	/* add url-list if one is specified */
	if (!LL_IS_EMPTY(m->web_seed_list)) {
		if (LL_IS_SINGLETON(m->web_seed_list)) {
			const char *first_web_seed =
				LL_DATA_AS(LL_HEAD(m->web_seed_list), const char*);

			err = fprintf(f, "8:url-list%lu:%s",
					(unsigned long) strlen(first_web_seed), first_web_seed);
			if (err < 0) {
				fprintf(stderr, "Error writing web seed URL\n");
				return -1;
			}
		} else {
			if (write_web_seed_list(f, m->web_seed_list) != 0) {
				return -1;
			}
		}
	}

	/* end the root dictionary */
	err = fprintf(f, "e");
	if (err < 0) {
		fprintf(stderr, "Error ending root dictionary\n");
		return -1;
	}

	/* Make sure data is flushed to disk */
	if (fflush(f) != 0) {
		fprintf(stderr, "Error flushing metainfo file to disk\n");
		return -1;
	}

	/* let the user know we're done already */
	printf("done\n");
	fflush(stdout);

	return 0;
}
