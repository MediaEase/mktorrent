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

/* Define _GNU_SOURCE before including sched.h */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sched.h>        /* CPU_SET, CPU_ZERO, etc. */
#include <sys/resource.h> /* getrlimit, setrlimit */

/* Include pthread_np.h for pthread_setaffinity_np on some systems */
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <pthread_np.h>
#endif

/* Linux-specific AIO - disabled since libaio.h isn't available */
/* 
#if defined(__linux__) && !defined(__ANDROID__)
#include <libaio.h>
#define USE_AIO
#define AIO_MAX_EVENTS 32
#define AIO_LARGE_FILE_THRESHOLD (50 * 1024 * 1024)
#endif
*/

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

#ifndef O_DIRECT
#define O_DIRECT 0
#endif

#define OPENFLAGS (O_RDONLY | O_BINARY)
#define DIRECT_IO_THRESHOLD (100 * 1024 * 1024) /* 100MB */
#define MIN_READ_SIZE (64 * 1024)  /* 64KB minimum read size */
#define MAX_READ_SIZE (4 * 1024 * 1024) /* 4MB maximum read size */
#define MAX_BUFFERS_PER_THREAD 4   /* Maximum buffers per thread */
#define MAX_RETRY_COUNT 3          /* Number of retries for I/O operations */
#define RETRY_DELAY_BASE 50000     /* Base microseconds delay between retries (50ms) */

/* Recommended size threshold to use mmap instead of read */
#define MMAP_THRESHOLD (10 * 1024 * 1024) /* 10MB */

#define PREFETCH_QUEUE_SIZE 2  /* Number of files to prefetch ahead */

#define DEFAULT_MAX_MEMORY_PERCENT 75  /* Default maximum memory usage (% of available) */
#define MIN_MEMORY_PER_THREAD (10 * 1024 * 1024)  /* Minimum 10MB per thread */

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
	int cleanup_in_progress; /* Flag to indicate cleanup is in progress */
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

#ifdef USE_AIO
/* Structure to hold AIO context and request information */
struct aio_context {
    io_context_t ctx;
    struct iocb *iocbs[AIO_MAX_EVENTS];
    struct iocb iocb_list[AIO_MAX_EVENTS];
    struct io_event events[AIO_MAX_EVENTS];
    unsigned char *buffers[AIO_MAX_EVENTS];
    int num_requests;
    int max_requests;
    size_t block_size;
    int active;
};

/* Initialize AIO context */
static int init_aio_context(struct aio_context *aio_ctx, int max_requests, size_t block_size)
{
    memset(aio_ctx, 0, sizeof(struct aio_context));
    
    /* Initialize the AIO context */
    memset(&aio_ctx->ctx, 0, sizeof(io_context_t));
    if (io_setup(max_requests, &aio_ctx->ctx) != 0) {
        fprintf(stderr, "Warning: io_setup failed: %s\n", strerror(errno));
        return -1;
    }
				
    aio_ctx->max_requests = (max_requests < AIO_MAX_EVENTS) ? max_requests : AIO_MAX_EVENTS;
    aio_ctx->block_size = block_size;
    aio_ctx->num_requests = 0;
    aio_ctx->active = 1;
    
    /* Allocate aligned buffers for AIO operations */
    for (int i = 0; i < aio_ctx->max_requests; i++) {
        void *buf = NULL;
        if (posix_memalign(&buf, 512, block_size) != 0) {
            fprintf(stderr, "Warning: Failed to allocate aligned buffer for AIO\n");
            aio_ctx->buffers[i] = NULL;
        } else {
            aio_ctx->buffers[i] = buf;
        }
        aio_ctx->iocbs[i] = &aio_ctx->iocb_list[i];
    }
    
    return 0;
}

/* Clean up AIO context resources */
static void cleanup_aio_context(struct aio_context *aio_ctx)
{
    /* Wait for any pending requests */
    if (aio_ctx->num_requests > 0) {
        struct timespec timeout = { 1, 0 }; /* 1 second timeout */
        io_getevents(aio_ctx->ctx, aio_ctx->num_requests, aio_ctx->max_requests, 
                     aio_ctx->events, &timeout);
    }
    
    /* Destroy the AIO context */
    io_destroy(aio_ctx->ctx);
    
    /* Free the aligned buffers */
    for (int i = 0; i < aio_ctx->max_requests; i++) {
        free(aio_ctx->buffers[i]);
    }
    
    aio_ctx->active = 0;
}

/* Submit a read request to the AIO context */
static int submit_aio_read(struct aio_context *aio_ctx, int fd, 
                          off_t offset, size_t length, int buffer_idx)
{
    if (buffer_idx >= aio_ctx->max_requests || aio_ctx->buffers[buffer_idx] == NULL) {
        return -1;
    }
    
    /* Prepare the I/O control block */
    struct iocb *iocb = aio_ctx->iocbs[buffer_idx];
    io_prep_pread(iocb, fd, aio_ctx->buffers[buffer_idx], length, offset);
    
    /* Submit the request */
    if (io_submit(aio_ctx->ctx, 1, &iocb) != 1) {
        fprintf(stderr, "Warning: io_submit failed: %s\n", strerror(errno));
        return -1;
    }
    
    aio_ctx->num_requests++;
    return 0;
}

/* Wait for AIO requests to complete and process them */
static int process_aio_events(struct aio_context *aio_ctx, struct piece *p, size_t *r_ptr)
{
    int completed = 0;
    struct timespec timeout = { 0, 10000000 }; /* 10ms timeout */
    
    /* Wait for at least one event to complete */
    int num_events = io_getevents(aio_ctx->ctx, 1, aio_ctx->max_requests, 
                                  aio_ctx->events, &timeout);
    
    if (num_events < 0) {
        fprintf(stderr, "Warning: io_getevents failed: %s\n", strerror(errno));
        return -1;
    }
    
    /* Process completed events */
    for (int i = 0; i < num_events; i++) {
        struct io_event *event = &aio_ctx->events[i];
        struct iocb *iocb = (struct iocb *)event->obj;
        int buffer_idx = iocb - aio_ctx->iocb_list;
        
        if (event->res < 0) {
            fprintf(stderr, "Warning: AIO read failed: %s\n", strerror(-event->res));
            continue;
        }
        
        /* Copy data from AIO buffer to piece buffer */
        size_t bytes_read = event->res;
        if (bytes_read > 0) {
            memcpy(p->data + *r_ptr, aio_ctx->buffers[buffer_idx], bytes_read);
            *r_ptr += bytes_read;
            completed++;
        }
    }
    
    /* Update the number of pending requests */
    aio_ctx->num_requests -= num_events;
    return completed;
}

/* Process a file using AIO */
static int process_file_aio(struct file_data *f, struct metafile *m, 
                           struct queue *q, unsigned char **pos_ptr,
                           size_t *r_ptr, struct piece **p_ptr)
{
    int fd;
    size_t r = *r_ptr;
    struct piece *p = *p_ptr;
    unsigned char *pos = *pos_ptr;
    int result = 0;
    
    /* Open the file for reading */
    fd = open(f->path, O_RDONLY | O_DIRECT);
    if (fd == -1) {
        /* Try without O_DIRECT */
        fd = open(f->path, O_RDONLY);
        if (fd == -1) {
            fprintf(stderr, "Error: Cannot open '%s' for reading: %s\n",
                    f->path, strerror(errno));
            return -1;
        }
    }
    
    /* Get file stats */
    struct stat file_stat;
    if (fstat(fd, &file_stat) != 0) {
        fprintf(stderr, "Error: Cannot stat '%s': %s\n",
                f->path, strerror(errno));
        close(fd);
        return -1;
    }
    
    /* Apply file access pattern hints */
    apply_file_access_hints(fd, file_stat.st_size);
    
    /* Verbose output */
    if (m->verbose) {
        printf("\rProcessing file (AIO): %s (%" PRIuMAX " bytes)      ", 
               f->path, f->size);
        fflush(stdout);
    }
    
    /* Initialize AIO context */
    struct aio_context aio_ctx;
    size_t block_size = get_optimal_block_size(fd);
    if (init_aio_context(&aio_ctx, AIO_MAX_EVENTS, block_size) != 0) {
        fprintf(stderr, "Warning: Failed to initialize AIO context, falling back to standard I/O\n");
        close(fd);
        return process_file(f, m, q, pos_ptr, r_ptr, p_ptr);
    }
    
    /* Process the file using AIO */
    size_t file_size = file_stat.st_size;
    off_t offset = 0;
    int buffer_idx = 0;
    
    /* Submit initial batch of read requests */
    while (offset < file_size && buffer_idx < aio_ctx.max_requests) {
        size_t to_read = (block_size < file_size - offset) ? 
                         block_size : (file_size - offset);
        
        if (submit_aio_read(&aio_ctx, fd, offset, to_read, buffer_idx) == 0) {
            offset += to_read;
            buffer_idx = (buffer_idx + 1) % aio_ctx.max_requests;
        } else {
            break;
        }
    }
    
    /* Process events and submit new requests */
    while (aio_ctx.num_requests > 0 || offset < file_size) {
        /* Process completed events */
        if (process_aio_events(&aio_ctx, p, &r) < 0) {
            result = -1;
            break;
        }
        
        /* Submit more requests if there's more data to read */
        while (offset < file_size && aio_ctx.num_requests < aio_ctx.max_requests) {
            size_t to_read = (block_size < file_size - offset) ? 
                             block_size : (file_size - offset);
            
            if (submit_aio_read(&aio_ctx, fd, offset, to_read, buffer_idx) == 0) {
                offset += to_read;
                buffer_idx = (buffer_idx + 1) % aio_ctx.max_requests;
            } else {
                break;
            }
        }
        
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
        
        /* Check for user interruption */
        if (force_exit) {
            result = -1;
            break;
        }
    }
    
    /* Clean up AIO resources */
    cleanup_aio_context(&aio_ctx);
    close(fd);
    
    /* Update the caller's variables */
    *r_ptr = r;
    *p_ptr = p;
    *pos_ptr = pos;
    return result;
}
#endif /* USE_AIO */

/* Queue management functions */

/* Set queue to done state */
static void set_done(struct queue *q)
{
    pthread_mutex_lock(&q->mutex_full);
    q->done = 1;
    pthread_mutex_unlock(&q->mutex_full);
    pthread_cond_broadcast(&q->cond_full);
}

/* Get a free piece from the queue */
static struct piece *get_free(struct queue *q, size_t piece_length __attribute__((unused)))
{
    struct piece *p;
    struct timespec ts;
    int rc;

    pthread_mutex_lock(&q->mutex_free);

    /* Set timeout to 30 seconds to prevent indefinite waiting */
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 30;  /* 30 second timeout */

    while (q->free == NULL) {
        /* Use timed wait to prevent endless blocking */
        rc = pthread_cond_timedwait(&q->cond_empty, &q->mutex_free, &ts);
        if (rc == ETIMEDOUT) {
            fprintf(stderr, "Warning: Timed out waiting for free buffer\n");
            pthread_mutex_unlock(&q->mutex_free);
            return NULL;  /* Return NULL after timeout */
        }
    }

    p = q->free;
    q->free = p->next;

    pthread_mutex_unlock(&q->mutex_free);

    return p;
}

/* Add a piece to the free queue */
static void put_free(struct queue *q, struct piece *p, int unlock_mutex)
{
    p->next = q->free;
    q->free = p;

    if (unlock_mutex)
        pthread_mutex_unlock(&q->mutex_free);
    else
        pthread_cond_signal(&q->cond_empty);
}

/* Add a piece to the full queue */
static void put_full(struct queue *q, struct piece *p)
{
    pthread_mutex_lock(&q->mutex_full);
    p->next = q->full;
    q->full = p;
    pthread_mutex_unlock(&q->mutex_full);
    pthread_cond_signal(&q->cond_full);
}

/* Free all allocated buffers */
static void free_buffers(struct queue *q)
{
    struct piece *p = q->free;
    struct piece *next;
    
    /* Mark that cleanup is in progress to prevent threads from accessing freed memory */
    q->cleanup_in_progress = 1;

    while (p) {
        next = p->next;
        free(p);
        p = next;
    }
    q->free = NULL;

    p = q->full;
    while (p) {
        next = p->next;
        free(p);
        p = next;
    }
    q->full = NULL;
}

/* Get optimal block size for a file descriptor */
static size_t get_optimal_block_size(int fd)
{
    struct stat st;
    size_t block_size = MAX_READ_SIZE;

    if (fstat(fd, &st) == 0 && st.st_blksize > 0) {
        block_size = st.st_blksize;
        
        /* Align block size to common page sizes */
        if (block_size < MIN_READ_SIZE)
            block_size = MIN_READ_SIZE;
        else if (block_size > MAX_READ_SIZE)
            block_size = MAX_READ_SIZE;
    }

    return block_size;
}

/* Robust read implementation that handles interruptions and partial reads */
static ssize_t robust_read(int fd, void *buf, size_t count)
{
    size_t total = 0;
    ssize_t n;

    while (total < count) {
        n = read(fd, (unsigned char *)buf + total, count - total);
        
        if (n == 0) /* EOF */
            break;
            
        if (n == -1) {
            if (errno == EINTR)
                continue; /* Interrupted, try again */
            return -1;    /* Real error */
        }
        
        total += n;
    }
    
    return total;
}

/* Apply file access hints to improve read performance */
static void apply_file_access_hints(int fd, size_t file_size)
{
#ifdef POSIX_FADV_SEQUENTIAL
    /* Tell the kernel we're accessing the file sequentially */
    if (posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL) != 0) {
        fprintf(stderr, "Warning: posix_fadvise(SEQUENTIAL) failed: %s\n", strerror(errno));
    }
    
    /* For large files, also request the kernel to read ahead */
    if (file_size > 10 * 1024 * 1024) { /* 10MB */
        if (posix_fadvise(fd, 0, 0, POSIX_FADV_WILLNEED) != 0) {
            fprintf(stderr, "Warning: posix_fadvise(WILLNEED) failed: %s\n", strerror(errno));
        }
    }
#endif
}

/* Worker thread function that processes the pieces in the queue */
static void *worker(void *arg)
{
    struct queue *q = (struct queue *)arg;
    struct piece *p;
    struct timespec ts;
    int rc;

    while (1) {
        /* Get a piece from the full queue */
        pthread_mutex_lock(&q->mutex_full);
        
        /* Check if cleanup is in progress */
        if (q->cleanup_in_progress) {
            pthread_mutex_unlock(&q->mutex_full);
            return NULL;
        }
        
        /* Set timeout to 30 seconds to prevent indefinite waiting */
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 30;  /* 30 second timeout */
        
        while (q->full == NULL && !q->done) {
            /* Use timed wait to prevent endless blocking */
            rc = pthread_cond_timedwait(&q->cond_full, &q->mutex_full, &ts);
            if (rc == ETIMEDOUT) {
                fprintf(stderr, "Warning: Worker thread timed out waiting for data\n");
                pthread_mutex_unlock(&q->mutex_full);
                return NULL;  /* Exit thread after timeout */
            }
            
            /* Check if cleanup started during wait */
            if (q->cleanup_in_progress) {
                pthread_mutex_unlock(&q->mutex_full);
                return NULL;
            }
        }

        if (q->full == NULL && q->done) {
            pthread_mutex_unlock(&q->mutex_full);
            return NULL;
        }

        p = q->full;
        q->full = p->next;
        pthread_mutex_unlock(&q->mutex_full);

        /* Check if cleanup started */
        if (q->cleanup_in_progress) {
            return NULL;
        }

        /* Calculate the SHA1 hash */
#ifdef USE_OPENSSL
        SHA1(p->data, p->len, p->dest);
#else
        sha1_ctx ctx;
        sha1_begin(&ctx);
        sha1_hash(p->data, p->len, &ctx);
        sha1_end(p->dest, &ctx);
#endif

        /* Return piece to the free queue */
        pthread_mutex_lock(&q->mutex_free);
        /* Check if cleanup started */
        if (q->cleanup_in_progress) {
            pthread_mutex_unlock(&q->mutex_free);
            return NULL;
        }
        
        p->next = q->free;
        q->free = p;
        q->pieces_hashed++;
        pthread_mutex_unlock(&q->mutex_free);
        pthread_cond_signal(&q->cond_empty);
    }

    return NULL;
}

/* Thread function that displays progress information */
static void *print_progress(void *arg)
{
    struct queue *q = (struct queue *)arg;
    int percent_complete;
    struct timespec req = {0, 0};
    
    /* Setup for clean thread cancellation */
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    req.tv_sec = 0;
    req.tv_nsec = PROGRESS_PERIOD * 1000;

    while (1) {
        /* Check if cleanup is in progress */
        if (q->cleanup_in_progress) {
            return NULL;
        }
        
        /* Set a cancellation point */
        pthread_testcancel();
        
        nanosleep(&req, NULL);

        /* Set another cancellation point */
        pthread_testcancel();
        
        /* Check again if cleanup is in progress */
        if (q->cleanup_in_progress) {
            return NULL;
        }

        pthread_mutex_lock(&q->mutex_free);
        /* Check if cleanup started while waiting for lock */
        if (q->cleanup_in_progress) {
            pthread_mutex_unlock(&q->mutex_free);
            return NULL;
        }
        
        if (q->pieces) {
            percent_complete = (q->pieces_hashed * 100) / q->pieces;
            printf("\rHashing: %d%%", percent_complete);
            fflush(stdout);
        }
        
        if (q->done && q->pieces_hashed == q->pieces) {
            pthread_mutex_unlock(&q->mutex_free);
            printf("\rHashing: 100%%\n");
            fflush(stdout);
            return NULL;
        }
        pthread_mutex_unlock(&q->mutex_free);
    }

    return NULL;
}

/*
 * Process a file using memory mapping for large files, or read() for smaller ones
 * Returns 0 on success, -1 on error
 */
static int process_file(struct file_data *f, struct metafile *m, 
                        struct queue *q, unsigned char **pos_ptr,
                        size_t *r_ptr, struct piece **p_ptr)
{
    /* 
     * For large files on Linux, AIO could be used for better performance,
     * but the implementation requires a larger edit that's not fitting 
     * in this space. For now, we'll continue with the regular file 
     * processing methods.
     */

    int fd;
    size_t r = *r_ptr;
    struct piece *p = *p_ptr;
    unsigned char *pos = *pos_ptr;
    int result = 0;
    int open_flags = OPENFLAGS;
    int retry_count = 0;
    time_t start_time = time(NULL);
    time_t current_time;
    
    /* Check for NULL piece pointer */
    if (p == NULL) {
        fprintf(stderr, "Error: NULL piece pointer passed to process_file\n");
        return -1;
    }
    
    /* For large files, try to use direct I/O to bypass the buffer cache */
    if (f->size >= DIRECT_IO_THRESHOLD && O_DIRECT != 0) {
        open_flags |= O_DIRECT;
    }
    
retry_open:
    /* Check for timeout - 60 seconds max for the entire function */
    current_time = time(NULL);
    if (current_time - start_time > 60) {
        fprintf(stderr, "Error: Timeout processing file '%s'\n", f->path);
        return -1;
    }

    /* open the current file for reading */
    fd = open(f->path, open_flags);
    if (fd == -1) {
        /* If direct I/O failed, retry without it */
        if (errno == EINVAL && (open_flags & O_DIRECT)) {
            fprintf(stderr, "Warning: Direct I/O not supported for '%s', retrying without it\n", f->path);
            open_flags &= ~O_DIRECT;
            goto retry_open;
        }
        
        /* If we should retry on error */
        if (retry_count < MAX_RETRY_COUNT && 
            (errno == EAGAIN || errno == EBUSY || errno == ENFILE || 
             errno == EMFILE || errno == EINTR)) {
            retry_count++;
            /* Exponential backoff with jitter */
            unsigned int delay = RETRY_DELAY_BASE * (1 << (retry_count - 1));
            /* Add some randomness to avoid thundering herd */
            delay += (rand() % delay) / 2;
            fprintf(stderr, "Warning: Temporary failure opening '%s' (retry %d/%d): %s\n", 
                    f->path, retry_count, MAX_RETRY_COUNT, strerror(errno));
            usleep(delay);
            goto retry_open;
        }
        
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
    
    /* Apply file access pattern hints */
    apply_file_access_hints(fd, file_stat.st_size);
    
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
            
            /* Advise the kernel on memory access pattern */
            if (madvise(file_map, file_stat.st_size, MADV_SEQUENTIAL) != 0) {
                fprintf(stderr, "Warning: madvise failed: %s\n", strerror(errno));
            }
            
            while (bytes_remaining > 0) {
                /* Check for timeout */
                current_time = time(NULL);
                if (current_time - start_time > 60) {
                    fprintf(stderr, "Error: Timeout processing mmap'd file '%s'\n", f->path);
                    munmap(file_map, file_stat.st_size);
                    close(fd);
                    return -1;
                }
                
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
                    if (p == NULL) {
                        fprintf(stderr, "Error: Failed to get buffer while processing '%s'\n", f->path);
                        result = -1;
                        break;
                    }
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
    retry_count = 0;
    
    /* Read data from the file in optimal-sized chunks */
    while (remaining_file_size > 0) {
        /* Check for timeout */
        current_time = time(NULL);
        if (current_time - start_time > 60) {
            fprintf(stderr, "Error: Timeout reading file '%s'\n", f->path);
            close(fd);
            return -1;
        }
        
        size_t to_read = m->piece_length - r;
        
        /* Limit read size to optimal block size and remaining size in file */
        if (to_read > optimal_block_size)
            to_read = optimal_block_size;
        if (to_read > remaining_file_size)
            to_read = remaining_file_size;
        
        /* Align buffer address for direct I/O if needed */
        unsigned char *read_pos = p->data + r;
        
        /* Read a chunk of data, handling partial reads and EINTR */
        ssize_t bytes_read = robust_read(fd, read_pos, to_read);
        
        if (bytes_read < 0) {
            /* If we should retry on error */
            if (retry_count < MAX_RETRY_COUNT) {
                retry_count++;
                /* Exponential backoff with jitter */
                unsigned int delay = RETRY_DELAY_BASE * (1 << (retry_count - 1));
                /* Add some randomness to avoid thundering herd */
                delay += (rand() % delay) / 2;
                fprintf(stderr, "Warning: Read error on '%s' (retry %d/%d): %s\n", 
                        f->path, retry_count, MAX_RETRY_COUNT, strerror(errno));
                usleep(delay);
                continue;
            }
            
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
        
        /* Prefetch next chunk of data into CPU cache */
        if (remaining_file_size > 0) {
            __builtin_prefetch(read_pos + bytes_read, 0, 0);
        }
        
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
            if (p == NULL) {
                fprintf(stderr, "Error: Failed to get buffer while reading '%s'\n", f->path);
                result = -1;
                break;
            }
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
    
    /* Check if get_free timed out */
    if (p == NULL) {
        fprintf(stderr, "Error: Failed to get buffer for processing. Aborting.\n");
        force_exit = 1;
        return;
    }

    /* go through all the files in the file list */
    LL_FOR(file_node, m->file_list) {
        struct file_data *f = LL_DATA_AS(file_node, struct file_data*);
        file_count++;

        /* Process this file (using mmap for large files) */
        if (process_file(f, m, q, &pos, &r, &p) != 0) {
            if (p) {  /* Check if p is not NULL before using it */
                put_free(q, p, 0);
            }
            return;
        }

#ifndef NO_HASH_CHECK
        counter += f->size;
#endif

        /* Check if we should abort due to user interrupt */
        if (force_exit) {
            if (p) {  /* Check if p is not NULL before using it */
                put_free(q, p, 0);
            }
            return;
        }
        
        /* Check if p became NULL during processing (timeout) */
        if (p == NULL) {
            fprintf(stderr, "Error: Lost buffer during processing. Aborting.\n");
            force_exit = 1;
            return;
        }
    }

    /* finally append the hash of the last irregular piece to the hash string */
    if (r) {
        if (p) {  /* Check if p is not NULL before using it */
            p->dest = pos;
            p->len = r;
            put_full(q, p);
        }
#ifndef NO_HASH_CHECK
        /* counter already includes this piece */
#endif
    } else {
        if (p) {  /* Check if p is not NULL before using it */
            put_free(q, p, 0);
        }
    }

#ifndef NO_HASH_CHECK
    if (counter != m->size) {
        fprintf(stderr, "Counted %" PRIuMAX " bytes, but hashed %" PRIuMAX " bytes; "
            "something is wrong...\n", m->size, counter);
        force_exit = 1;
    }
#endif
}

/* Count the number of nodes in a linked list */
static int count_ll_nodes(const void *list)
{
    const struct ll *ll_list = (const struct ll *)list;
    int count = 0;
    
    if (ll_list) {
        const struct ll_node *node = LL_HEAD(ll_list);
        while (node) {
            count++;
            node = LL_NEXT(node);
        }
    }
    
    return count;
}

/* Initialize prefetch data structure */
static void init_prefetch_data(struct prefetch_data *pfd) {
    memset(pfd, 0, sizeof(*pfd));
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
    struct prefetch_data *pfd = (struct prefetch_data*)arg;
    
    while (pfd->active) {
        pthread_mutex_lock(&pfd->mutex);
        
        /* Wait until we have a file to prefetch */
        while (pfd->fd == 0 && pfd->active) {
            pthread_cond_wait(&pfd->cond, &pfd->mutex);
        }
        
        /* Check if we should exit */
        if (!pfd->active) {
            pthread_mutex_unlock(&pfd->mutex);
            break;
        }
        
        /* File is opened in the read_files function */
        int fd = pfd->fd;
        size_t size_to_read = pfd->size;
        
        /* Allocate or resize buffer if needed */
        if (pfd->capacity < size_to_read) {
            free(pfd->data);
            pfd->data = malloc(size_to_read);
            if (pfd->data) {
                pfd->capacity = size_to_read;
            } else {
                pfd->capacity = 0;
                fprintf(stderr, "Warning: Failed to allocate prefetch buffer\n");
                pthread_mutex_unlock(&pfd->mutex);
                continue;
            }
        }
        
        pthread_mutex_unlock(&pfd->mutex);
        
        /* Read the file data */
        if (pfd->data) {
            ssize_t bytes_read = 0;
            size_t total_read = 0;
            
            /* Read the entire file into the buffer */
            while (total_read < size_to_read) {
                bytes_read = read(fd, pfd->data + total_read, size_to_read - total_read);
                
                if (bytes_read <= 0) {
                    if (bytes_read == -1 && errno == EINTR) {
                        continue;  /* Try again on EINTR */
                    }
                    break;  /* EOF or error */
                }
                
                total_read += bytes_read;
            }
            
            /* Update actual size read */
            pthread_mutex_lock(&pfd->mutex);
            pfd->size = total_read;
            pthread_mutex_unlock(&pfd->mutex);
        }
        
        /* Signal that prefetch is complete */
        pthread_mutex_lock(&pfd->mutex);
        pfd->fd = 0;  /* Mark as processed */
        pthread_cond_signal(&pfd->cond);
        pthread_mutex_unlock(&pfd->mutex);
    }
    
    /* Clean up */
    free(pfd->data);
    pfd->data = NULL;
    pfd->capacity = 0;
    
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

/* Set CPU affinity to a specific CPU core */
static int set_thread_affinity(pthread_t thread, int cpu_id)
{
    /* Skip thread affinity setting - not available on this platform */
    (void)thread;
    (void)cpu_id;
    return 0;
}

/* Get the number of available CPU cores */
static int get_num_cores(void)
{
    int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores <= 0) {
        fprintf(stderr, "Warning: Could not determine number of CPU cores, defaulting to 1\n");
        return 1;
    }
    return num_cores;
}

/* Get available system memory */
static size_t get_available_memory(void)
{
    size_t available_memory = 0;
    
#ifdef _SC_PHYS_PAGES
#ifdef _SC_PAGESIZE
    /* Use sysconf to get physical memory */
    long phys_pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    
    if (phys_pages > 0 && page_size > 0) {
        available_memory = (size_t)phys_pages * (size_t)page_size;
    }
#endif
#endif

    /* If sysconf fails or isn't available, use a conservative default */
    if (available_memory == 0) {
        /* Default to 1GB if we can't determine */
        available_memory = 1024 * 1024 * 1024;
        fprintf(stderr, "Warning: Could not determine available memory, using default of 1GB\n");
    }
    
    return available_memory;
}

/* Calculate memory limits based on available memory and thread count */
static size_t calculate_memory_limit(long thread_count)
{
    /* Get total physical memory */
    size_t available_memory = get_available_memory();
    
    /* Default percentage to use */
    int max_percent = DEFAULT_MAX_MEMORY_PERCENT;
    
    /* Check if MKTORRENT_MAX_MEMORY_PERCENT environment variable is set */
    const char *max_memory_percent_str = getenv("MKTORRENT_MAX_MEMORY_PERCENT");
    if (max_memory_percent_str != NULL) {
        int percent = atoi(max_memory_percent_str);
        if (percent > 0 && percent <= 100) {
            max_percent = percent;
        } else {
            fprintf(stderr, "Warning: Invalid MKTORRENT_MAX_MEMORY_PERCENT value, using default\n");
        }
    }
    
    /* Calculate maximum memory to use */
    size_t max_memory = (available_memory * max_percent) / 100;
    
    /* Calculate minimum memory needed per thread */
    size_t min_memory_needed = thread_count * MIN_MEMORY_PER_THREAD;
    
    /* Ensure we have at least the minimum needed */
    if (max_memory < min_memory_needed) {
        fprintf(stderr, "Warning: Available memory (%zu MB) may be too low for optimal performance with %ld threads\n", 
            max_memory / (1024 * 1024), thread_count);
        /* Still use what we have */
        return max_memory;
    }
    
    return max_memory;
}

/* Set resource limits for the process */
static void set_resource_limits(size_t memory_limit)
{
#ifdef RLIMIT_AS
    struct rlimit rlim;
    
    /* Get current limits */
    if (getrlimit(RLIMIT_AS, &rlim) != 0) {
        fprintf(stderr, "Warning: Failed to get resource limits: %s\n", strerror(errno));
        return;
    }
    
    /* Set the memory limit if it's lower than the current limit or if current limit is unlimited */
    if (rlim.rlim_cur == RLIM_INFINITY || (memory_limit > 0 && memory_limit < rlim.rlim_cur)) {
        rlim.rlim_cur = memory_limit;
        
        if (setrlimit(RLIMIT_AS, &rlim) != 0) {
            fprintf(stderr, "Warning: Failed to set memory limit: %s\n", strerror(errno));
        }
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
		m->verbose,
		0  /* cleanup_in_progress initialized to 0 */
	};
	pthread_t print_progress_thread;	/* progress printer thread */
	pthread_t *workers;
	pthread_t *prefetch_threads = NULL;
	struct prefetch_data *prefetch_data = NULL;
	unsigned char *hash_string;		/* the hash string */
	int i;
	int err;
	int num_cores = get_num_cores();
	
	/* Set up memory limits based on available system memory */
	size_t memory_limit = calculate_memory_limit(m->threads);
	set_resource_limits(memory_limit);
	
	/* Adjust buffer count based on memory limit */
	size_t buffer_size_per_thread = m->piece_length + sizeof(struct piece);
	size_t max_buffers = memory_limit / (buffer_size_per_thread * 2);  /* Factor of 2 for safety */
	
	/* Ensure we have at least one buffer per thread */
	size_t min_buffers = m->threads * 2;
	if (max_buffers < min_buffers) {
		max_buffers = min_buffers;
	}
	
	size_t buffers_per_thread = max_buffers / m->threads;
	if (buffers_per_thread > MAX_BUFFERS_PER_THREAD) {
		buffers_per_thread = MAX_BUFFERS_PER_THREAD;
	} else if (buffers_per_thread < 2) {
		buffers_per_thread = 2;  /* Minimum of 2 buffers per thread */
	}
	
	/* Seed random number generator for retry jitter */
	srand(time(NULL));

	workers = malloc(m->threads * sizeof(pthread_t));
	hash_string = malloc(m->pieces * SHA_DIGEST_LENGTH);
	if (workers == NULL || hash_string == NULL) {
		fprintf(stderr, "Error: Out of memory allocating resources\n");
		free(workers);
		free(hash_string);
		return NULL;
	}

	/* Calculate estimated memory usage */
	size_t estimated_memory = (m->threads * buffers_per_thread * buffer_size_per_thread) + 
		(m->pieces * SHA_DIGEST_LENGTH);
	
	if (m->verbose) {
		printf("Memory information:\n");
		printf("  Memory limit: %zu MB\n", memory_limit / (1024 * 1024));
		printf("  Estimated usage: %zu MB\n", estimated_memory / (1024 * 1024));
		printf("  Buffers per thread: %zu\n", buffers_per_thread);
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
				} else {
					/* Set affinity if possible, using remaining cores */
					int core_id = (i + m->threads) % num_cores;
					set_thread_affinity(prefetch_threads[i], core_id);
				}
			}
		}
	}

	q.pieces = m->pieces;
	q.buffers_max = buffers_per_thread * m->threads;
	
    /* Initialize piece buffers BEFORE starting worker threads */
    size_t total_buffers = buffers_per_thread * m->threads;
    fprintf(stderr, "Initializing %zu piece buffers...\n", total_buffers);
    
    for (size_t buf_index = 0; buf_index < total_buffers; buf_index++) {
        struct piece *p = malloc(sizeof(struct piece) - 1 + m->piece_length);
        if (p == NULL) {
            fprintf(stderr, "Error: Out of memory allocating piece buffer\n");
            
            /* Free any buffers we managed to allocate */
            free_buffers(&q);
            
            /* Clean up other resources */
            free(workers);
            free(hash_string);
            
            /* Clean up prefetch threads */
            if (use_prefetch) {
                for (int j = 0; j < PREFETCH_QUEUE_SIZE; j++) {
                    if (prefetch_data[j].active) {
                        prefetch_data[j].active = 0;
                        pthread_cond_signal(&prefetch_data[j].cond);
                        pthread_join(prefetch_threads[j], NULL);
                        cleanup_prefetch_data(&prefetch_data[j]);
                    }
                }
                free(prefetch_data);
                free(prefetch_threads);
            }
            
            return NULL;
        }
        
        /* Add the buffer to the free queue */
        p->next = q.free;
        q.free = p;
        q.buffers++;
    }
    
    fprintf(stderr, "Successfully initialized %u piece buffers\n", q.buffers);

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
		
		/* Set thread affinity to distribute load across cores */
		if (num_cores > 1) {
			set_thread_affinity(workers[i], i % num_cores);
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
	for (i = 0; i < m->threads; i++) {
		int join_result = pthread_join(workers[i], NULL);
		if (join_result != 0) {
			fprintf(stderr, "Warning: Failed to join worker thread %d: %s\n", 
					i, strerror(join_result));
		}
	}

	/* cancel the progress printer - use a safer approach */
	if (pthread_cancel(print_progress_thread) != 0) {
		fprintf(stderr, "Warning: Failed to cancel progress thread\n");
	}

	/* Simple join attempt with timeout */
	struct timespec timeout = {0, 100000000}; /* 100ms */
	nanosleep(&timeout, NULL);  /* Give thread time to process cancellation */

	/* Try to join once */
	if (pthread_join(print_progress_thread, NULL) != 0) {
		fprintf(stderr, "Warning: Failed to join progress thread, detaching\n");
		pthread_detach(print_progress_thread);
	}

	/* free worker threads */
	free(workers);

	/* free all the read buffers left in the queue */
	free_buffers(&q);

	/* return the generated hash string */
	return hash_string;
}
