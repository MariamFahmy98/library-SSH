#include "../include/scp.h"

int get_local_file(char *file_path, char **file_content) {
  char *result = NULL;
  FILE *file = NULL;
  *file_content = NULL;
  char buffer[50];
  
  file = fopen(file_path, "r");

  memset(buffer, 0, sizeof(buffer));

  if (file == NULL) {
    fprintf(stderr, "Error: %s\n", strerror(errno));
    return -1;
  }

  if (fgets(buffer, sizeof(buffer), file) == NULL) {
    fprintf(stderr, "Error %s\n", strerror(errno));
    return -1;
  }

  result = malloc(strlen(buffer) + 1);
  memset(result, 0, strlen(buffer) + 1);
  memcpy(result, &buffer, strlen(buffer) + 1);

  *file_content = result;
  fclose(file);
  return 0;
}

int scp_send_directory(ssh_session session, ssh_scp scp) {
  int rc;
  char *buf = NULL;

  rc = ssh_scp_push_directory(scp, "remote_directory", S_IRWXU);
  if (rc != SSH_OK) {
    fprintf(stderr, "Can't create remote directory: %s\n",
            ssh_get_error(session));
    return -1;
  }

  rc = ssh_scp_push_file(scp, "file1.txt", 50, S_IRUSR | S_IWUSR);
  if (rc != SSH_OK) {
    fprintf(stderr, "Can't open remote file: %s\n", ssh_get_error(session));
    return -1;
  }

  if (get_local_file("local_directory/file1.txt", &buf) < 0) {
    return -1;
  }

  rc = ssh_scp_write(scp, buf , 50);
  if (rc != SSH_OK) {
    fprintf(stderr, "Can't write to remote file: %s\n", ssh_get_error(session));
    return -1;
  }

  rc = ssh_scp_push_file(scp, "file2.txt", 50, S_IRUSR | S_IWUSR);
  if (rc != SSH_OK) {
    fprintf(stderr, "Can't open remote file: %s\n", ssh_get_error(session));
    return -1;
  }

  if (get_local_file("local_directory/file2.txt", &buf) < 0) {
    return -1;
  }

  rc = ssh_scp_write(scp, buf, 50);
  if (rc != SSH_OK) {
    fprintf(stderr, "Can't write to remote file: %s\n", ssh_get_error(session));
    return rc;
  }

  free(buf);
  return 0;
}