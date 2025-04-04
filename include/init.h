#ifndef MKTORRENT_INIT_H
#define MKTORRENT_INIT_H

#include "export.h"    /* EXPORT */
#include "mktorrent.h" /* struct metafile */

EXPORT void cleanup_metafile(struct metafile *m);
EXPORT int init(struct metafile *m, int argc, char *argv[]);

#endif /* MKTORRENT_INIT_H */
