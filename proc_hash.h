/*
 * proc_hash.h:
 *
 */

#ifndef __PROC_HASH_H_ /* include guard */
#define __PROC_HASH_H_

#include <stdint.h>
#include <sys/socket.h>
#include <stdbool.h>
#include "hash.h"

typedef struct {
    uint16_t port;
    char* name;
} ip_process;

hash_type* proc_hash_create(void);
void proc_hash_init_refresh(hash_type* sh, bool refresh);

#endif /* __PROC_HASH_H_ */
