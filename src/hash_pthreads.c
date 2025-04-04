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
#include <sys/mman.h>     /* mmap(), munmap() */

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

/* Recommended size threshold to use mmap instead of read */
#define MMAP_THRESHOLD (10 * 1024 * 1024) /* 10MB */

#define PREFETCH_QUEUE_SIZE 2  /* Number of files to prefetch ahead */

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

/* Structure to hold prefetched file data */
struct prefetch_data {
    unsigned char *data;
    size_t size;
    size_t capacity;
    int fd;
    char *path;
    int active;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

static struct piece *get_free(struct queue *q, size_t piece_length)
{
	struct piece *r;

	pthread_mutex_lock(&q->mutex_free);
	if (q->free) {
		r = q->free;
		q->free = r->next;
	} else if (q->buffers < q->buffers_max) {
		/* Allocate aligned memory for better cache performance */
		size_t alloc_size = sizeof(struct piece) - 1 + piece_length;
		
		/* Align to cache line boundary (typically 64 bytes) */
		#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L
			/* Use posix_memalign for aligned allocation */
			void *mem = NULL;
			if (posix_memalign(&mem, 64, alloc_size) != 0) {
				fprintf(stderr, "Error: Failed to allocate aligned memory\n");
				r = NULL;
			} else {
				r = (struct piece *)mem;
			}
		#else
			/* Fallback for systems without posix_memalign */
			/* Add extra space for alignment */
			void *mem = malloc(alloc_size + 64);
			if (mem == NULL) {
				r = NULL;
			} else {
				/* Align to 64-byte boundary */
				uintptr_t addr = (uintptr_t)mem;
				addr = (addr + 63) & ~(uintptr_t)63; /* Round up to 64-byte boundary */
				r = (struct piece *)addr;
				
				/* Store original pointer for freeing later */
				*((void **)r - 1) = mem;
			}
		#endif
		
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
		
		#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L
			/* For posix_memalign, just free the pointer directly */
			free(current);
		#else
			/* For custom alignment, get the original pointer first */
			void *original = *((void **)current - 1);
			free(original);
		#endif
		
		current = next;
	}

	/* Also free any pieces in the full queue that weren't processed */
	current = q->full;
	while (current) {
		next = current->next;
		
		#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L
			free(current);
		#else
			void *original = *((void **)current - 1);
			free(original);
		#endif
		
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

	/* Use cache-aligned buffer for output to avoid false sharing */
	unsigned char hash_buffer[SHA_DIGEST_LENGTH] __attribute__((aligned(64)));

	while ((p = get_full(q))) {
		/* Process data in chunks that fit better in CPU cache */
		const size_t OPTIMAL_CHUNK_SIZE = 65536; /* 64KB - good balance for cache efficiency */
		size_t remaining = p->len;
		size_t offset = 0;

#ifdef USE_OPENSSL
		/* Initialize the hash context */
		if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
			fprintf(stderr, "Error: Failed to initialize SHA1 hash\n");
			put_free(q, p, 1); /* Still mark as processed */
			continue;
		}
		
		/* Process the data in cache-friendly chunks */
		while (remaining > 0) {
			size_t chunk_size = (remaining > OPTIMAL_CHUNK_SIZE) ? 
								 OPTIMAL_CHUNK_SIZE : remaining;
			
			if (EVP_DigestUpdate(ctx, p->data + offset, chunk_size) != 1) {
				fprintf(stderr, "Error: Failed during SHA1 update\n");
				break;
			}
			
			offset += chunk_size;
			remaining -= chunk_size;
		}
		
		/* Finalize the hash and store in aligned buffer first */
		if (EVP_DigestFinal_ex(ctx, hash_buffer, &md_len) != 1) {
			fprintf(stderr, "Error: Failed to finalize SHA1 hash\n");
		}
		
		/* Copy to destination */
		memcpy(p->dest, hash_buffer, SHA_DIGEST_LENGTH);
#else
		/* Initialize the hash context */
		SHA1_Init(&c);
		
		/* Process the data in cache-friendly chunks */
		while (remaining > 0) {
			size_t chunk_size = (remaining > OPTIMAL_CHUNK_SIZE) ? 
								 OPTIMAL_CHUNK_SIZE : remaining;
			
			SHA1_Update(&c, p->data + offset, chunk_size);
			
			offset += chunk_size;
			remaining -= chunk_size;
		}
		
		/* Finalize the hash and store in aligned buffer first */
		SHA1_Final(hash_buffer, &c);
		
		/* Copy to destination */
		memcpy(p->dest, hash_buffer, SHA_DIGEST_LENGTH);
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

/*
 * Process a file using memory mapping for large files, or read() for smaller ones
 * Returns 0 on success, -1 on error
 */
static int process_file(struct file_data *f, struct metafile *m, 
                       struct queue *q, unsigned char **pos_ptr,
                       size_t *r_ptr, struct piece **p_ptr)
{
    int fd;
    size_t r = *r_ptr;
    struct piece *p = *p_ptr;
    unsigned char *pos = *pos_ptr;
    int result = 0;
    
    /* open the current file for reading */
    fd = open(f->path, OPENFLAGS);
    if (fd == -1) {
        fprintf(stderr, "Cannot open '%s' for reading: %s\n", 
            f->path, strerror(errno));
        return -1;
    }
    
    /* Get file stats */
    struct stat file_stat;
    if (fstat(fd, &file_stat) != 0) {
        fprintf(stderr, "Cannot stat '%s': %s\n", 
            f->path, strerror(errno));
        close(fd);
        return -1;
    }
    
    /* Verbose output */
    if (m->verbose) {
        printf("\rProcessing file: %s (%" PRIuMAX " bytes)      ", 
            f->path, f->size);
        fflush(stdout);
    }
    
    /* For large files, use memory mapping to reduce I/O overhead */
    if (file_stat.st_size >= MMAP_THRESHOLD) {
        void *file_map = mmap(NULL, file_stat.st_size, PROT_READ, 
                              MAP_PRIVATE, fd, 0);
        
        if (file_map == MAP_FAILED) {
            fprintf(stderr, "Cannot mmap '%s': %s. Falling back to read.\n", 
                f->path, strerror(errno));
        } else {
            /* Process the file using memory mapping */
            unsigned char *file_data = (unsigned char *)file_map;
            size_t bytes_remaining = file_stat.st_size;
            size_t offset = 0;
            
            while (bytes_remaining > 0) {
                /* Fill the current piece buffer */
                size_t to_copy = m->piece_length - r;
                if (to_copy > bytes_remaining) {
                    to_copy = bytes_remaining;
                }
                
                /* Copy data from mmaped region to piece buffer */
                memcpy(p->data + r, file_data + offset, to_copy);
                r += to_copy;
                offset += to_copy;
                bytes_remaining -= to_copy;
                
                /* If we filled a piece, queue it for hashing */
                if (r == m->piece_length) {
                    p->dest = pos;
                    p->len = m->piece_length;
                    put_full(q, p);
                    pos += SHA_DIGEST_LENGTH;
                    r = 0;
                    
                    /* Check if we should abort due to user interrupt */
                    if (force_exit) {
                        result = -1;
                        break;
                    }
                    
                    /* Get a new piece buffer */
                    p = get_free(q, m->piece_length);
                }
            }
            
            /* Unmap the file */
            munmap(file_map, file_stat.st_size);
            close(fd);
            
            /* Return early, we're done with this file */
            *r_ptr = r;
            *p_ptr = p;
            *pos_ptr = pos;
            return result;
        }
    }
    
    /* Fallback to using read for smaller files or if mmap failed */
    size_t optimal_block_size = get_optimal_block_size(fd);
    uintmax_t remaining_file_size = f->size;
    
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
            result = -1;
            break;
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
            r = 0;
            
            /* Check if we should abort due to user interrupt */
            if (force_exit) {
                result = -1;
                break;
            }
            
            /* Get a new piece buffer */
            p = get_free(q, m->piece_length);
        }
    }
    
    /* Close the file */
    if (close(fd) != 0) {
        fprintf(stderr, "Cannot close '%s': %s\n",
            f->path, strerror(errno));
    }
    
    /* Update the caller's variables */
    *r_ptr = r;
    *p_ptr = p;
    *pos_ptr = pos;
    return result;
}

static void read_files(struct metafile *m, struct queue *q, unsigned char *pos)
{
    size_t r = 0;          /* number of bytes read from file(s)
                              into the read buffer */
#ifndef NO_HASH_CHECK
    uintmax_t counter = 0; /* number of bytes hashed
                              should match size when done */
#endif
    struct piece *p = get_free(q, m->piece_length);
    int file_count = 0;

    /* go through all the files in the file list */
    LL_FOR(file_node, m->file_list) {
        struct file_data *f = LL_DATA_AS(file_node, struct file_data*);
        file_count++;

        /* Process this file (using mmap for large files) */
        if (process_file(f, m, q, &pos, &r, &p) != 0) {
            put_free(q, p, 0);
            return;
        }

#ifndef NO_HASH_CHECK
        counter += f->size;
#endif

        /* Check if we should abort due to user interrupt */
        if (force_exit) {
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
        /* counter already includes this piece */
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

/* Initialize prefetch data structure */
static void init_prefetch_data(struct prefetch_data *pfd) {
    pfd->data = NULL;
    pfd->size = 0;
    pfd->capacity = 0;
    pfd->fd = -1;
    pfd->path = NULL;
    pfd->active = 0;
    pthread_mutex_init(&pfd->mutex, NULL);
    pthread_cond_init(&pfd->cond, NULL);
}

/* Free resources associated with prefetch data */
static void cleanup_prefetch_data(struct prefetch_data *pfd) {
    if (pfd->fd >= 0) {
        close(pfd->fd);
        pfd->fd = -1;
    }
    
    free(pfd->data);
    pfd->data = NULL;
    pfd->size = 0;
    pfd->capacity = 0;
    
    free(pfd->path);
    pfd->path = NULL;
    
    pfd->active = 0;
}

/* Prefetch thread function to read files ahead */
static void *prefetch_worker(void *arg) {
    struct prefetch_data *pfd = (struct prefetch_data *)arg;
    size_t optimal_read_size;
    
    pthread_mutex_lock(&pfd->mutex);
    
    while (pfd->active) {
        /* Wait until we're given a file to prefetch */
        while (pfd->active && pfd->fd < 0) {
            pthread_cond_wait(&pfd->cond, &pfd->mutex);
        }
        
        /* If we're no longer active, exit */
        if (!pfd->active) {
            pthread_mutex_unlock(&pfd->mutex);
            return NULL;
        }
        
        /* Temporarily unlock while reading */
        pthread_mutex_unlock(&pfd->mutex);
        
        /* Get optimal block size for this file */
        optimal_read_size = get_optimal_block_size(pfd->fd);
        
        /* Allocate or resize buffer if needed */
        if (pfd->capacity < optimal_read_size) {
            pthread_mutex_lock(&pfd->mutex);
            pfd->capacity = optimal_read_size;
            pfd->data = realloc(pfd->data, pfd->capacity);
            if (!pfd->data) {
                fprintf(stderr, "Error: Failed to allocate prefetch buffer\n");
                pfd->capacity = 0;
                pthread_mutex_unlock(&pfd->mutex);
                continue;
            }
            pthread_mutex_unlock(&pfd->mutex);
        }
        
        /* Read data from file */
        pthread_mutex_lock(&pfd->mutex);
        pfd->size = 0;
        pthread_mutex_unlock(&pfd->mutex);
        
        /* Loop to read the file in chunks */
        while (1) {
            ssize_t bytes_read;
            
            /* If we've been told to stop, break out */
            pthread_mutex_lock(&pfd->mutex);
            if (pfd->fd < 0 || !pfd->active) {
                pthread_mutex_unlock(&pfd->mutex);
                break;
            }
            
            /* Ensure we have space in the buffer */
            if (pfd->size + optimal_read_size > pfd->capacity) {
                size_t new_capacity = pfd->capacity * 2;
                unsigned char *new_data = realloc(pfd->data, new_capacity);
                
                if (!new_data) {
                    fprintf(stderr, "Error: Failed to resize prefetch buffer\n");
                    pthread_mutex_unlock(&pfd->mutex);
                    break;
                }
                
                pfd->data = new_data;
                pfd->capacity = new_capacity;
            }
            pthread_mutex_unlock(&pfd->mutex);
            
            /* Read more data */
            bytes_read = read(pfd->fd, pfd->data + pfd->size, optimal_read_size);
            
            pthread_mutex_lock(&pfd->mutex);
            
            if (bytes_read <= 0) {
                /* End of file or error */
                if (bytes_read < 0 && errno != EINTR) {
                    fprintf(stderr, "Warning: Error reading prefetch data from '%s': %s\n",
                            pfd->path, strerror(errno));
                }
                pthread_mutex_unlock(&pfd->mutex);
                break;
            }
            
            /* Update size */
            pfd->size += bytes_read;
            pthread_mutex_unlock(&pfd->mutex);
            
            /* Check for cancellation */
            if (force_exit) {
                break;
            }
        }
        
        /* We're done reading this file, signal that it's ready */
        pthread_mutex_lock(&pfd->mutex);
        pthread_cond_signal(&pfd->cond);
        pthread_mutex_unlock(&pfd->mutex);
    }
    
    pthread_mutex_unlock(&pfd->mutex);
    return NULL;
}

/* Start prefetching a file */
static int start_prefetch(struct prefetch_data *pfd, const char *path) {
    pthread_mutex_lock(&pfd->mutex);
    
    /* Clean up any previous prefetch */
    if (pfd->fd >= 0) {
        close(pfd->fd);
        pfd->fd = -1;
    }
    
    free(pfd->path);
    pfd->path = strdup(path);
    if (!pfd->path) {
        pthread_mutex_unlock(&pfd->mutex);
        return -1;
    }
    
    /* Open the file */
    pfd->fd = open(path, OPENFLAGS);
    if (pfd->fd < 0) {
        fprintf(stderr, "Error: Cannot open '%s' for prefetching: %s\n",
                path, strerror(errno));
        free(pfd->path);
        pfd->path = NULL;
        pthread_mutex_unlock(&pfd->mutex);
        return -1;
    }
    
    /* Reset size and signal worker to start prefetching */
    pfd->size = 0;
    pthread_cond_signal(&pfd->cond);
    
    pthread_mutex_unlock(&pfd->mutex);
    return 0;
}

/* Wait for prefetch to complete and return the data */
static int get_prefetched_data(struct prefetch_data *pfd, unsigned char **data, 
                               size_t *size, int *fd) __attribute__((unused));
static int get_prefetched_data(struct prefetch_data *pfd, unsigned char **data, 
                               size_t *size, int *fd) {
    pthread_mutex_lock(&pfd->mutex);
    
    /* If no file is being prefetched, return error */
    if (pfd->fd < 0) {
        pthread_mutex_unlock(&pfd->mutex);
        return -1;
    }
    
    /* Return the current data, size, and file descriptor */
    *data = pfd->data;
    *size = pfd->size;
    *fd = pfd->fd;
    
    /* Reset the file descriptor so the prefetch thread doesn't do more work */
    pfd->fd = -1;
    pfd->data = NULL;
    pfd->size = 0;
    pfd->capacity = 0;
    
    /* Prefetch thread is responsible for closing the file */
    
    pthread_mutex_unlock(&pfd->mutex);
    return 0;
}

/*
 * Count the number of nodes in a linked list
 */
static unsigned int count_ll_nodes(struct ll *list)
{
    unsigned int count = 0;
    
    if (!list)
        return 0;
        
    LL_FOR(node, list) {
        count++;
    }
    
    return count;
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
	pthread_t *prefetch_threads = NULL;
	struct prefetch_data *prefetch_data = NULL;
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

	/* Set up prefetch system if we have files to process */
	int use_prefetch = count_ll_nodes(m->file_list) > 1;
	
	if (use_prefetch) {
		prefetch_data = malloc(PREFETCH_QUEUE_SIZE * sizeof(struct prefetch_data));
		prefetch_threads = malloc(PREFETCH_QUEUE_SIZE * sizeof(pthread_t));
		
		if (prefetch_data == NULL || prefetch_threads == NULL) {
			fprintf(stderr, "Warning: Failed to allocate prefetch structures. Continuing without prefetching.\n");
			free(prefetch_data);
			free(prefetch_threads);
			prefetch_data = NULL;
			prefetch_threads = NULL;
			use_prefetch = 0;
		} else {
			/* Initialize prefetch data structures and start threads */
			for (i = 0; i < PREFETCH_QUEUE_SIZE; i++) {
				init_prefetch_data(&prefetch_data[i]);
				prefetch_data[i].active = 1;
				
				err = pthread_create(&prefetch_threads[i], NULL, prefetch_worker, &prefetch_data[i]);
				if (err) {
					fprintf(stderr, "Warning: Cannot create prefetch thread: %s\n", strerror(err));
					prefetch_data[i].active = 0;
					/* Continue with reduced prefetch capability */
				}
			}
		}
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
			
			/* Clean up prefetch threads */
			if (use_prefetch) {
				for (i = 0; i < PREFETCH_QUEUE_SIZE; i++) {
					if (prefetch_data[i].active) {
						prefetch_data[i].active = 0;
						pthread_cond_signal(&prefetch_data[i].cond);
						pthread_join(prefetch_threads[i], NULL);
						cleanup_prefetch_data(&prefetch_data[i]);
					}
				}
				free(prefetch_data);
				free(prefetch_threads);
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
		
		/* Clean up prefetch threads */
		if (use_prefetch) {
			for (i = 0; i < PREFETCH_QUEUE_SIZE; i++) {
				if (prefetch_data[i].active) {
					prefetch_data[i].active = 0;
					pthread_cond_signal(&prefetch_data[i].cond);
					pthread_join(prefetch_threads[i], NULL);
					cleanup_prefetch_data(&prefetch_data[i]);
				}
			}
			free(prefetch_data);
			free(prefetch_threads);
		}
		
		free(workers);
		free(hash_string);
		free_buffers(&q);
		return NULL;
	}

	/* If we have prefetch capability, start prefetching the first files */
	if (use_prefetch) {
		struct ll_node *node = LL_HEAD(m->file_list);
		int prefetch_idx = 0;
		
		/* Start prefetching the initial files */
		while (node != NULL && prefetch_idx < PREFETCH_QUEUE_SIZE) {
			struct file_data *f = LL_DATA_AS(node, struct file_data*);
			if (start_prefetch(&prefetch_data[prefetch_idx], f->path) == 0) {
				prefetch_idx++;
			}
			node = LL_NEXT(node);
		}
	}

	/* read files and feed pieces to the workers */
	read_files(m, &q, hash_string);

	/* Stop prefetch threads */
	if (use_prefetch) {
		for (i = 0; i < PREFETCH_QUEUE_SIZE; i++) {
			if (prefetch_data[i].active) {
				prefetch_data[i].active = 0;
				pthread_cond_signal(&prefetch_data[i].cond);
				pthread_join(prefetch_threads[i], NULL);
				cleanup_prefetch_data(&prefetch_data[i]);
			}
		}
		free(prefetch_data);
		free(prefetch_threads);
	}

	/* we're done, let the pieces in the queue be hashed and collected */
	set_done(&q);

	/* wait for the worker threads to signal completion */
	for (i = 0; i < m->threads; i++)
		pthread_join(workers[i], NULL);

	/* cancel the progress printer */
	pthread_cancel(print_progress_thread);
	pthread_join(print_progress_thread, NULL);

	/* free worker threads */
	free(workers);

	/* free all the read buffers left in the queue */
	free_buffers(&q);

	/* return the generated hash string */
	return hash_string;
}
