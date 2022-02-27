#ifndef SCP_H
#define SCP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libssh/libssh.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int get_local_file(char *file_path, char **file_content);

int scp_send_directory(ssh_session session, ssh_scp scp);

#ifdef __cplusplus
}
#endif

#endif