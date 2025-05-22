#ifndef __SECRET_H
#define __SECRET_H

#ifndef SECRET_SIZE /* only define it if not already defined */
#define SECRET_SIZE 8192
#endif

#include <sys/ucred.h>

typedef struct dev_data {
  char secret[SECRET_SIZE]; /* Secret buffer */
  uucred owner; /* Owner of the secret */
  char *read_ptr; /* Current position of read */
  char *write_ptr; /* Current position of write */
  int open_count; /* count of open file descriptors for secret */
} dev_data;

#endif /* __SECRET_H */
