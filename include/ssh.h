#ifndef SSH_H
#define SSH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libssh/libssh.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int verify_knownhosts(ssh_session session);

int authenticate_public_key(ssh_session session);

#ifdef __cplusplus
}
#endif

#endif