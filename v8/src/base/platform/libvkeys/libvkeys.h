#pragma once

#include <unistd.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define syscall_vkey_reg_lib    335
#define syscall_vkey_alloc      336
#define syscall_vkey_free       337
#define syscall_vkey_mprotect   338
#define syscall_vkey_reg_vkru   339
#define syscall_vkey_activate   340

#define VKEY_AD     0x1		/* access  disable */
#define VKEY_WD     0x2		/* write   disable */
#define VKEY_ND     0x0		/* nothing disable */
#define VKEY_PINNED 0x3

#define VKEY_AD_INIT    0x5 /* access   disable when init */
#define VKEY_WD_INIT    0x6 /* write    disable when init */
#define VKEY_ND_INIT    0x4 /* nothing  disable when init */
#define VKEY_MASK       0x4

#define VKEY_SPROT  0x1     /* self protection vkey */

#define MAX_VKEY_PER_SPACE  14
#define MAX_VKEY_PER_PROC   128
#define VKEY_META_DATA_SZ   8192
#define INTEL_L1_BYTES      64
#define VKEY_TRAMP_MAX_SZ   8192

typedef struct {
    char perm[MAX_VKEY_PER_PROC / 4];   /* 32 bytes, another 32 bytes as the safe stack */
    char stack[INTEL_L1_BYTES - MAX_VKEY_PER_PROC / 4];
} vkru_t;

__attribute__ ((visibility("default"))) int vkey_init(bool sprot);  /* self prot */
__attribute__ ((visibility("default"))) int vkey_alloc(void);       /* syscall */
__attribute__ ((visibility("default"))) int vkey_free(int vkey);    /* syscall */
__attribute__ ((visibility("default"))) int vkey_mprotect(void *addr, size_t len, int vkey);    /* syscall */
__attribute__ ((visibility("default"))) vkru_t *vkru_alloc(int nas);   /* self prot */
__attribute__ ((visibility("default"))) void vkru_free(void);       /* self prot */
__attribute__ ((visibility("default"))) void wrvkru(int vkey, int perm);    /* self prot */
__attribute__ ((visibility("default"))) int rdvkru(int vkey);       /* self prot */
__attribute__ ((visibility("default"))) int vkey_ready(void);       /* self prot */

#ifdef __cplusplus
}
#endif
