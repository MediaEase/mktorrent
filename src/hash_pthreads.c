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

/* This file should only be compiled if USE_PTHREADS is defined */
#ifndef USE_PTHREADS
#error "This file should only be compiled with pthreads support"
#endif

#include <stdlib.h>       /* exit(), malloc() */
#include <sys/types.h>    /* off_t */
#include <errno.h>        /* errno */
#include <string.h>       /* strerror() */
#include <stdio.h>        /* printf() etc. */
#include <fcntl.h>        /* open() */
#include <unistd.h>       /* read(), close() */
#include <inttypes.h>     /* PRId64 etc. */
#include <pthread.h>
#include <time.h>         /* nanosleep() */
#include <sys/stat.h>     /* fstat() */
#include <signal.h>

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

#ifndef PROGRESS_PERIOD
#define PROGRESS_PERIOD 200000
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define OPENFLAGS (O_RDONLY | O_BINARY)
#define MIN_READ_SIZE (64 * 1024)  /* 64KB minimum read size */
#define MAX_READ_SIZE (4 * 1024 * 1024) /* 4MB maximum read size */
#define MAX_BUFFERS_PER_THREAD 4   /* Maximum buffers per thread */

/* External declaration of the force_exit flag for clean shutdowns */
extern volatile int force_exit;

struct piece {
	struct piece *next;
	unsigned char *dest;
	unsigned long len;
	unsigned char data[1];  /* flexible array member */
};

struct queue {
	struct piece *free;
	struct piece *full;
	unsigned int buffers_max;
	unsigned int buffers;
	pthread_mutex_t mutex_free;
	pthread_mutex_t mutex_full;
	pthread_cond_t cond_empty;
	pthread_cond_t cond_full;
	unsigned int done;
	unsigned int pieces;
	unsigned int pieces_hashed;
	int verbose;
};

static struct piece *get_free(struct queue *q, size_t piece_length)
{
	struct piece *r;

	pthread_mutex_lock(&q->mutex_free);
	if (q->free) {
		r = q->free;
		q->free = r->next;
	} else if (q->buffers < q->buffers_max) {
		r = malloc(sizeof(struct piece) - 1 + piece_length);
		FATAL_IF0(r == NULL, "out of memory\n");
		q->buffers++;
	} else {
		while (q->free == NULL) {
			pthread_cond_wait(&q->cond_full, &q->mutex_free);
		}

		r = q->free;
		q->free = r->next;
	}
	pthread_mutex_unlock(&q->mutex_free);

	return r;
}

static struct piece *get_full(struct queue *q)
{
	struct piece *r;

	pthread_mutex_lock(&q->mutex_full);
again:
	if (q->full) {
		r = q->full;
		q->full = r->next;
	} else if (q->done) {
		r = NULL;
	} else {
		pthread_cond_wait(&q->cond_empty, &q->mutex_full);
		goto again;
	}
	pthread_mutex_unlock(&q->mutex_full);

	return r;
}

static void put_free(struct queue *q, struct piece *p, unsigned int hashed)
{
	pthread_mutex_lock(&q->mutex_free);
	p->next = q->free;
	q->free = p;
	q->pieces_hashed += hashed;
	pthread_mutex_unlock(&q->mutex_free);
	pthread_cond_signal(&q->cond_full);
}

static void put_full(struct queue *q, struct piece *p)
{
	pthread_mutex_lock(&q->mutex_full);
	p->next = q->full;
	q->full = p;
	pthread_mutex_unlock(&q->mutex_full);
	pthread_cond_signal(&q->cond_empty);
}

static void set_done(struct queue *q)
{
	pthread_mutex_lock(&q->mutex_full);
	q->done = 1;
	pthread_mutex_unlock(&q->mutex_full);
	pthread_cond_broadcast(&q->cond_empty);
}

static void free_buffers(struct queue *q)
{
	struct piece *current = q->free;
	struct piece *next;

	while (current) {
		next = current->next;
		free(current);
		current = next;
	}

	/* Also free any pieces in the full queue that weren't processed */
	current = q->full;
	while (current) {
		next = current->next;
		free(current);
		current = next;
	}

	q->free = NULL;
	q->full = NULL;
}

/*
 * print the progress in a thread of its own
 */
static void *print_progress(void *data)
{
	struct queue *q = data;
	int err;
	struct timespec t;
	unsigned int last_pieces_hashed = 0;
	unsigned int current_speed = 0;
	time_t last_update_time = time(NULL);
	time_t start_time = last_update_time;
	size_t piece_length = 0;  /* We'll set this from the metafile */
	uintmax_t bytes_per_second = 0;
	uintmax_t total_bytes = 0;
	double eta_seconds = 0;
	
	/* Find out the piece length by checking a piece buffer */
	pthread_mutex_lock(&q->mutex_full);
	if (q->full) {
		piece_length = q->full->len;
	} else {
		pthread_mutex_lock(&q->mutex_free);
		if (q->free) {
			piece_length = q->free->len;
		}
		pthread_mutex_unlock(&q->mutex_free);
	}
	pthread_mutex_unlock(&q->mutex_full);

	t.tv_sec = PROGRESS_PERIOD / 1000000;
	t.tv_nsec = PROGRESS_PERIOD % 1000000 * 1000;

	err = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	if (err) {
		fprintf(stderr, "Warning: Cannot set thread cancel type: %s\n", strerror(err));
	}

	while (1) {
		/* Calculate hashing speed and ETA */
		time_t current_time = time(NULL);
		time_t elapsed = current_time - last_update_time;
		time_t total_elapsed = current_time - start_time;
		
		if (elapsed >= 1) {
			unsigned int pieces_done = q->pieces_hashed - last_pieces_hashed;
			current_speed = pieces_done / elapsed;
			
			/* Calculate bytes per second if we know the piece length */
			if (piece_length > 0 && current_speed > 0) {
				bytes_per_second = (uintmax_t)current_speed * piece_length;
				total_bytes = (uintmax_t)q->pieces_hashed * piece_length;
			}
			
			/* Calculate ETA */
			if (current_speed > 0 && q->pieces > 0) {
				unsigned int pieces_left = q->pieces - q->pieces_hashed;
				eta_seconds = (double)pieces_left / current_speed;
			}
			
			last_pieces_hashed = q->pieces_hashed;
			last_update_time = current_time;
		}

		/* print progress and flush the buffer immediately */
		float percentage = q->pieces > 0 ? 
			(float)q->pieces_hashed * 100 / q->pieces : 0;
			
		/* Display remaining time in appropriate units */
		char eta_str[50] = "calculating...";
		if (current_speed > 0) {
			if (eta_seconds < 60) {
				snprintf(eta_str, sizeof(eta_str), "%.0fs", eta_seconds);
			} else if (eta_seconds < 3600) {
				snprintf(eta_str, sizeof(eta_str), "%.1fm", eta_seconds / 60);
			} else {
				snprintf(eta_str, sizeof(eta_str), "%.1fh", eta_seconds / 3600);
			}
		}
		
		/* Format throughput in appropriate units */
		char speed_str[50] = "";
		if (bytes_per_second > 0) {
			if (bytes_per_second < 1024 * 1024) {
				snprintf(speed_str, sizeof(speed_str), " at %.1f KB/s", 
					bytes_per_second / 1024.0);
			} else {
				snprintf(speed_str, sizeof(speed_str), " at %.2f MB/s", 
					bytes_per_second / (1024.0 * 1024.0));
			}
		}
		
		/* Show elapsed time and total bytes processed */
		char elapsed_str[100] = "";
		if (total_elapsed > 0) {
			char time_part[50];
			char bytes_part[50] = "";
			
			if (total_elapsed < 60) {
				snprintf(time_part, sizeof(time_part), "[%lds]", total_elapsed);
			} else if (total_elapsed < 3600) {
				snprintf(time_part, sizeof(time_part), "[%ldm %lds]", 
					total_elapsed / 60, total_elapsed % 60);
			} else {
				snprintf(time_part, sizeof(time_part), "[%ldh %ldm]", 
					total_elapsed / 3600, (total_elapsed % 3600) / 60);
			}
			
			if (total_bytes > 0) {
				if (total_bytes < 1024 * 1024) {
					snprintf(bytes_part, sizeof(bytes_part), " %.1f KB", 
						total_bytes / 1024.0);
				} else if (total_bytes < 1024 * 1024 * 1024) {
					snprintf(bytes_part, sizeof(bytes_part), " %.2f MB", 
						total_bytes / (1024.0 * 1024.0));
				} else {
					snprintf(bytes_part, sizeof(bytes_part), " %.2f GB", 
						total_bytes / (1024.0 * 1024.0 * 1024.0));
				}
			}
			
			snprintf(elapsed_str, sizeof(elapsed_str), " %s%s", time_part, bytes_part);
		}
		
		if (q->verbose) {
			printf("\rHashed %u of %u pieces (%.1f%%)%s%s - ETA: %s  ", 
				q->pieces_hashed, q->pieces, percentage,
				speed_str, elapsed_str, eta_str);
		} else {
			printf("\rHashed %u of %u pieces.", q->pieces_hashed, q->pieces);
		}
		fflush(stdout);
		
		/* now sleep for PROGRESS_PERIOD microseconds */
		nanosleep(&t, NULL);
	}

	return NULL;
}

static void *worker(void *data)
{
	struct queue *q = data;
	struct piece *p;
#ifdef USE_OPENSSL
	/* Use the modern EVP API when OpenSSL is available */
	EVP_MD_CTX *ctx = NULL;
	const EVP_MD *md = NULL;
	unsigned int md_len = 0;
	
	/* Initialize the EVP context */
	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Error: Failed to create EVP context\n");
		return NULL;
	}
	
	/* Get the SHA1 message digest */
	md = EVP_sha1();
	if (!md) {
		fprintf(stderr, "Error: Failed to get SHA1 digest\n");
		EVP_MD_CTX_free(ctx);
		return NULL;
	}
#else
	SHA_CTX c;
#endif

	while ((p = get_full(q))) {
#ifdef USE_OPENSSL
		/* Use EVP interface for modern OpenSSL */
		if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
			EVP_DigestUpdate(ctx, p->data, p->len) != 1 ||
			EVP_DigestFinal_ex(ctx, p->dest, &md_len) != 1) {
			fprintf(stderr, "Error: Failed to calculate SHA1 hash\n");
		}
#else
		SHA1_Init(&c);
		SHA1_Update(&c, p->data, p->len);
		SHA1_Final(p->dest, &c);
#endif
		put_free(q, p, 1);
	}

#ifdef USE_OPENSSL
	/* Clean up EVP context */
	EVP_MD_CTX_free(ctx);
#endif

	return NULL;
}

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

static void read_files(struct metafile *m, struct queue *q, unsigned char *pos)
{
	int fd;                /* file descriptor */
	size_t r = 0;          /* number of bytes read from file(s)
	                          into the read buffer */
#ifndef NO_HASH_CHECK
	uintmax_t counter = 0; /* number of bytes hashed
	                          should match size when done */
#endif
	struct piece *p = get_free(q, m->piece_length);
	size_t optimal_block_size;
	int file_count = 0;

	/* go through all the files in the file list */
	LL_FOR(file_node, m->file_list) {
		struct file_data *f = LL_DATA_AS(file_node, struct file_data*);
		uintmax_t remaining_file_size = f->size;
		file_count++;

		/* open the current file for reading */
		fd = open(f->path, OPENFLAGS);
		if (fd == -1) {
			fprintf(stderr, "Cannot open '%s' for reading: %s\n", 
				f->path, strerror(errno));
			put_free(q, p, 0);
			return;
		}
		
		/* Get optimal block size for this file */
		optimal_block_size = get_optimal_block_size(fd);
		
		/* Verbose output */
		if (m->verbose) {
			printf("\rProcessing file %d: %s (%"PRIuMAX" bytes)      ", 
				file_count, f->path, f->size);
			fflush(stdout);
		}

		/* Read data from the file in optimal-sized chunks */
		while (remaining_file_size > 0) {
			size_t to_read = m->piece_length - r;
			
			/* Limit read size to optimal block size and remaining size in file */
			if (to_read > optimal_block_size)
				to_read = optimal_block_size;
			if (to_read > remaining_file_size)
				to_read = remaining_file_size;
			
			/* Read a chunk of data, handling partial reads and EINTR */
			ssize_t bytes_read = robust_read(fd, p->data + r, to_read);
			
			if (bytes_read < 0) {
				fprintf(stderr, "Cannot read from '%s': %s\n",
					f->path, strerror(errno));
				close(fd);
				put_free(q, p, 0);
				return;
			}
			
			if (bytes_read == 0) /* End of file */
				break;
			
			r += bytes_read;
			remaining_file_size -= bytes_read;

			/* Check if we filled a piece */
			if (r == m->piece_length) {
				p->dest = pos;
				p->len = m->piece_length;
				put_full(q, p);
				pos += SHA_DIGEST_LENGTH;
#ifndef NO_HASH_CHECK
				counter += r;
#endif
				r = 0;
				
				/* Check if we should abort due to user interrupt */
				if (force_exit) {
					close(fd);
					return;
				}
				
				/* Get a new piece buffer */
				p = get_free(q, m->piece_length);
			}
		}

		/* now close the file */
		if (close(fd) != 0) {
			fprintf(stderr, "Cannot close '%s': %s\n",
				f->path, strerror(errno));
			put_free(q, p, 0);
			return;
		}
	}

	/* finally append the hash of the last irregular piece to the hash string */
	if (r) {
		p->dest = pos;
		p->len = r;
		put_full(q, p);
#ifndef NO_HASH_CHECK
		counter += r;
#endif
	} else {
		put_free(q, p, 0);
	}

#ifndef NO_HASH_CHECK
	if (counter != m->size) {
		fprintf(stderr, "Counted %" PRIuMAX " bytes, but hashed %" PRIuMAX " bytes; "
			"something is wrong...\n", m->size, counter);
		force_exit = 1;
	}
#endif
}

EXPORT unsigned char *make_hash(struct metafile *m)
{
	struct queue q = {
		NULL, NULL, 0, 0,
		PTHREAD_MUTEX_INITIALIZER,
		PTHREAD_MUTEX_INITIALIZER,
		PTHREAD_COND_INITIALIZER,
		PTHREAD_COND_INITIALIZER,
		0, 0, 0,
		m->verbose
	};
	pthread_t print_progress_thread;	/* progress printer thread */
	pthread_t *workers;
	unsigned char *hash_string;		/* the hash string */
	int i;
	int err;

	workers = malloc(m->threads * sizeof(pthread_t));
	hash_string = malloc(m->pieces * SHA_DIGEST_LENGTH);
	if (workers == NULL || hash_string == NULL) {
		fprintf(stderr, "Error: Out of memory allocating resources\n");
		free(workers);
		free(hash_string);
		return NULL;
	}

	q.pieces = m->pieces;
	q.buffers_max = MAX_BUFFERS_PER_THREAD * m->threads;

	/* create worker threads */
	for (i = 0; i < m->threads; i++) {
		err = pthread_create(&workers[i], NULL, worker, &q);
		if (err) {
			fprintf(stderr, "Error: Cannot create thread: %s\n", strerror(err));
			/* Terminate any already created threads */
			while (--i >= 0) {
				pthread_cancel(workers[i]);
				pthread_join(workers[i], NULL);
			}
			free(workers);
			free(hash_string);
			free_buffers(&q);
			return NULL;
		}
	}

	/* now set off the progress printer */
	err = pthread_create(&print_progress_thread, NULL, print_progress, &q);
	if (err) {
		fprintf(stderr, "Error: Cannot create progress thread: %s\n", strerror(err));
		for (i = 0; i < m->threads; i++) {
			pthread_cancel(workers[i]);
			pthread_join(workers[i], NULL);
		}
		free(workers);
		free(hash_string);
		free_buffers(&q);
		return NULL;
	}

	/* read files and feed pieces to the workers */
	read_files(m, &q, hash_string);

	/* Check if we've been asked to abort */
	if (force_exit) {
		fprintf(stderr, "\nHashing cancelled by user...\n");
		for (i = 0; i < m->threads; i++) {
			pthread_cancel(workers[i]);
			pthread_join(workers[i], NULL);
		}
		pthread_cancel(print_progress_thread);
		pthread_join(print_progress_thread, NULL);
		free(workers);
		free(hash_string);
		free_buffers(&q);
		return NULL;
	}

	/* we're done so stop printing our progress. */
	err = pthread_cancel(print_progress_thread);
	if (err) {
		fprintf(stderr, "Warning: Cannot cancel thread: %s\n", strerror(err));
	}

	/* inform workers we're done */
	set_done(&q);

	/* wait for workers to finish */
	for (i = 0; i < m->threads; i++) {
		err = pthread_join(workers[i], NULL);
		if (err) {
			fprintf(stderr, "Warning: Cannot join thread: %s\n", strerror(err));
		}
	}

	free(workers);

	/* the progress printer should be done by now too */
	err = pthread_join(print_progress_thread, NULL);
	if (err) {
		fprintf(stderr, "Warning: Cannot join thread: %s\n", strerror(err));
	}

	/* destroy mutexes and condition variables */
	pthread_mutex_destroy(&q.mutex_full);
	pthread_mutex_destroy(&q.mutex_free);
	pthread_cond_destroy(&q.cond_empty);
	pthread_cond_destroy(&q.cond_full);

	/* free buffers */
	free_buffers(&q);

	/* ok, let the user know we're done too */
	printf("\rHashed %u of %u pieces (100.0%%)\n", q.pieces_hashed, q.pieces);

	return hash_string;
}
