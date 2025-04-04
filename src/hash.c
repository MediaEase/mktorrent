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
#include <errno.h>        /* errno */
#include <string.h>       /* strerror() */
#include <stdio.h>        /* printf() etc. */
#include <fcntl.h>        /* open() */
#include <unistd.h>       /* read(), close() */
#include <inttypes.h>     /* PRId64 etc. */

#ifdef USE_OPENSSL
#include <openssl/sha.h>  /* SHA1() */
#include <openssl/evp.h>  /* EVP interface for modern SHA1 usage */
#else
#include "sha1.h"
#endif

#include "export.h"
#include "mktorrent.h"
#include "hash.h"
#include "msg.h"
#include "ll.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define OPENFLAGS (O_RDONLY | O_BINARY)
#define MIN_READ_SIZE (64 * 1024)  /* 64KB minimum read size */
#define MAX_READ_SIZE (4 * 1024 * 1024) /* 4MB maximum read size */

/* External declaration of the force_exit flag */
extern volatile int force_exit;

/*
 * Get optimal block size for a file
 */
static size_t get_optimal_block_size(int fd)
{
	struct stat file_stat;
	size_t block_size = MIN_READ_SIZE;
	
	if (fstat(fd, &file_stat) == 0) {
		/* Get file system's preferred block size */
		if (file_stat.st_blksize > MIN_READ_SIZE) {
			block_size = file_stat.st_blksize;
		}
		
		/* Cap the block size at a reasonable maximum */
		if (block_size > MAX_READ_SIZE) {
			block_size = MAX_READ_SIZE;
		}
	}
	
	return block_size;
}

/*
 * Reads data from fd into buffer, handling partial reads and retrying on interrupts
 * Returns total bytes read, or -1 on error
 */
static ssize_t robust_read(int fd, unsigned char *buf, size_t count)
{
	ssize_t total_read = 0;
	ssize_t bytes_read;
	
	while (count > 0) {
		bytes_read = read(fd, buf, count);
		
		if (bytes_read < 0) {
			/* EINTR means we were interrupted by a signal */
			if (errno == EINTR)
				continue;
			
			/* Real error occurred */
			return -1;
		}
		
		if (bytes_read == 0) /* End of file */
			break;
		
		buf += bytes_read;
		count -= bytes_read;
		total_read += bytes_read;
	}
	
	return total_read;
}

/*
 * go through the files in file_list, split their contents into pieces
 * of size piece_length and create the hash string, which is the
 * concatenation of the (20 byte) SHA1 hash of every piece
 * last piece may be shorter
 */
EXPORT unsigned char *make_hash(struct metafile *m)
{
	unsigned char *hash_string;     /* the hash string */
	unsigned char *pos;             /* position in the hash string */
	unsigned char *read_buf;        /* read buffer */
	int fd;                         /* file descriptor */
	size_t r;                       /* number of bytes read from file(s) into
	                                   the read buffer */
#ifdef USE_OPENSSL
	EVP_MD_CTX *ctx = NULL;
	const EVP_MD *md = NULL;
	unsigned int md_len = 0;
#else
	SHA_CTX c;                      /* SHA1 hashing context */
#endif
#ifndef NO_HASH_CHECK
	uintmax_t counter = 0;          /* number of bytes hashed
	                                   should match size when done */
#endif
	int file_count = 0;
	size_t optimal_block_size;

	/* allocate memory for the hash string
	   every SHA1 hash is SHA_DIGEST_LENGTH (20) bytes long */
	hash_string = malloc(m->pieces * SHA_DIGEST_LENGTH);
	/* allocate memory for the read buffer to store 1 piece */
	read_buf = malloc(m->piece_length);

	/* check if we've run out of memory */
	if (hash_string == NULL || read_buf == NULL) {
		fprintf(stderr, "Error: out of memory\n");
		free(hash_string);
		free(read_buf);
		return NULL;
	}

#ifdef USE_OPENSSL
	/* Initialize the EVP context */
	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Error: Failed to create EVP context\n");
		free(hash_string);
		free(read_buf);
		return NULL;
	}
	
	/* Get the SHA1 message digest */
	md = EVP_sha1();
	if (!md) {
		fprintf(stderr, "Error: Failed to get SHA1 digest\n");
		EVP_MD_CTX_free(ctx);
		free(hash_string);
		free(read_buf);
		return NULL;
	}
#endif

	/* initiate pos to point to the beginning of hash_string */
	pos = hash_string;
	/* and initiate r to 0 since we haven't read anything yet */
	r = 0;
	/* go through all the files in the file list */
	LL_FOR(file_node, m->file_list) {
		struct file_data *f = LL_DATA_AS(file_node, struct file_data*);
		uintmax_t remaining_file_size = f->size;
		file_count++;

		/* open the current file for reading */
		fd = open(f->path, OPENFLAGS);
		if (fd == -1) {
			fprintf(stderr, "Error: Cannot open '%s' for reading: %s\n", 
				f->path, strerror(errno));
			free(read_buf);
			free(hash_string);
#ifdef USE_OPENSSL
			EVP_MD_CTX_free(ctx);
#endif
			return NULL;
		}
		
		/* Get optimal block size for this file */
		optimal_block_size = get_optimal_block_size(fd);
		
		printf("hashing %s\n", f->path);
		fflush(stdout);

		/* Read data from the file in optimal-sized chunks */
		while (remaining_file_size > 0 && !force_exit) {
			size_t to_read = m->piece_length - r;
			
			/* Limit read size to optimal block size and remaining size in file */
			if (to_read > optimal_block_size)
				to_read = optimal_block_size;
			if (to_read > remaining_file_size)
				to_read = remaining_file_size;
			
			/* Read a chunk of data, handling partial reads and EINTR */
			ssize_t bytes_read = robust_read(fd, read_buf + r, to_read);
			
			if (bytes_read < 0) {
				fprintf(stderr, "Error: Cannot read from '%s': %s\n",
					f->path, strerror(errno));
				close(fd);
				free(read_buf);
				free(hash_string);
#ifdef USE_OPENSSL
				EVP_MD_CTX_free(ctx);
#endif
				return NULL;
			}
			
			if (bytes_read == 0) /* End of file */
				break;
			
			r += bytes_read;
			remaining_file_size -= bytes_read;

			/* Check if we filled a piece */
			if (r == m->piece_length) {
#ifdef USE_OPENSSL
				/* Use EVP interface for modern OpenSSL */
				if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
					EVP_DigestUpdate(ctx, read_buf, m->piece_length) != 1 ||
					EVP_DigestFinal_ex(ctx, pos, &md_len) != 1) {
					fprintf(stderr, "Error: Failed to calculate SHA1 hash\n");
					close(fd);
					free(read_buf);
					free(hash_string);
					EVP_MD_CTX_free(ctx);
					return NULL;
				}
#else
				SHA1_Init(&c);
				SHA1_Update(&c, read_buf, m->piece_length);
				SHA1_Final(pos, &c);
#endif
				pos += SHA_DIGEST_LENGTH;
#ifndef NO_HASH_CHECK
				counter += r;	/* r == piece_length */
#endif
				r = 0;
			}
		}

		/* Check for user interrupt */
		if (force_exit) {
			fprintf(stderr, "\nHashing cancelled by user...\n");
			close(fd);
			free(read_buf);
			free(hash_string);
#ifdef USE_OPENSSL
			EVP_MD_CTX_free(ctx);
#endif
			return NULL;
		}

		/* now close the file */
		if (close(fd) != 0) {
			fprintf(stderr, "Error: Cannot close '%s': %s\n",
				f->path, strerror(errno));
		}
	}

	/* finally append the hash of the last irregular piece to the hash string */
	if (r) {
#ifdef USE_OPENSSL
		/* Use EVP interface for modern OpenSSL */
		if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
			EVP_DigestUpdate(ctx, read_buf, r) != 1 ||
			EVP_DigestFinal_ex(ctx, pos, &md_len) != 1) {
			fprintf(stderr, "Error: Failed to calculate SHA1 hash\n");
			free(read_buf);
			free(hash_string);
			EVP_MD_CTX_free(ctx);
			return NULL;
		}
#else
		SHA1_Init(&c);
		SHA1_Update(&c, read_buf, r);
		SHA1_Final(pos, &c);
#endif
	}

#ifndef NO_HASH_CHECK
	counter += r;
	if (counter != m->size) {
		fprintf(stderr, "Error: Counted %" PRIuMAX " bytes, but hashed %" PRIuMAX " bytes; "
			"something is wrong...\n", m->size, counter);
		free(read_buf);
		free(hash_string);
#ifdef USE_OPENSSL
		EVP_MD_CTX_free(ctx);
#endif
		return NULL;
	}
#endif

#ifdef USE_OPENSSL
	/* Clean up EVP context */
	EVP_MD_CTX_free(ctx);
#endif

	/* free the read buffer before we return */
	free(read_buf);

	return hash_string;
}
