#ifndef __SECRET_H
#define __SECRET_H

#ifndef SECRET_SIZE /* only define it if not already defined */
#define SECRET_SIZE 8192
#endif

#include <sys/ucred.h>
typedef struct ucred ucred;

typedef struct dev_data {
  char secret[SECRET_SIZE]; /* Secret buffer */
  int is_empty; /* 1 if empty, 0 if full */
  uid_t owner_uid; /* Owner of the secret */
  int read_pos; /* Current position of read */
  int write_pos; /* Current position of write. Also the number of bytes written */
  int open_count; /* count of open file descriptors for secret */
} dev_data;

#endif /* __SECRET_H */
