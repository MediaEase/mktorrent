#ifndef MKTORRENT_OUTPUT_H
#define MKTORRENT_OUTPUT_H

#include <stdio.h>       /* FILE */

#include "export.h"    /* EXPORT */
#include "mktorrent.h" /* struct metafile */

#ifndef CREATED_BY
#define CREATED_BY "mktorrent"
#endif

#ifndef CREATED_BY_SUFFIX
#define CREATED_BY_SUFFIX " " VERSION
#endif

EXPORT int write_metainfo(FILE *f, struct metafile *m, unsigned char *hash_string);

#endif /* MKTORRENT_OUTPUT_H */
