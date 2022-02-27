#include "../include/ssh.h"

int verify_knownhosts(ssh_session session)
{
  enum ssh_known_hosts_e state;
  unsigned char *public_key_hash = NULL;
  ssh_key server_public_key;
  size_t hash_length;
  char buf[10];
  char *hexa;
  char *p;
  int compare;
  int rc;

  rc = ssh_get_server_publickey(session, &server_public_key);
  if (rc < 0) {
    ssh_key_free(server_public_key);
    return -1;
  }

  rc = ssh_get_publickey_hash(server_public_key, SSH_PUBLICKEY_HASH_SHA1,
                              &public_key_hash, &hash_length);
  ssh_key_free(server_public_key);

  if (rc < 0) {
    ssh_clean_pubkey_hash(&public_key_hash);
    return -1;
  }

  state = ssh_session_is_known_server(session);
  switch (state) {
  case SSH_KNOWN_HOSTS_OK:
    break;
  case SSH_KNOWN_HOSTS_CHANGED:
    fprintf(stderr, "Host key for server changed: it is now:\n");
    ssh_print_hash(SSH_PUBLICKEY_HASH_SHA1, public_key_hash, hash_length);
    fprintf(stderr, "For security reasons, connection will be stopped\n");
    ssh_clean_pubkey_hash(&public_key_hash);

    return -1;
  case SSH_KNOWN_HOSTS_OTHER:
    fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
    fprintf(stderr,
            "An attacker might change the default server key to"
            "confuse your client into thinking the key does not exist\n");
    ssh_clean_pubkey_hash(&public_key_hash);

    return -1;
  case SSH_KNOWN_HOSTS_NOT_FOUND:
    fprintf(stderr, "Could not find known host file.\n");
    fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");
  case SSH_KNOWN_HOSTS_UNKNOWN:
    hexa = ssh_get_hexa(public_key_hash, hash_length);

    fprintf(stderr, "The server is unknown. Do you trust the host key?\n");
    fprintf(stderr, "Public key hash: %s\n", hexa);

    ssh_string_free_char(hexa);
    ssh_clean_pubkey_hash(&public_key_hash);

    p = fgets(buf, sizeof(buf), stdin);
    if (p == NULL) {
      return -1;
    }

    compare = strncasecmp(p, "yes", 3);
    if (compare != 0) {
      return -1;
    }

    rc = ssh_session_update_known_hosts(session);
    if (rc < 0) {
      fprintf(stderr, "Error %s\n", strerror(errno));
      return -1;
    }
    break;
  case SSH_KNOWN_HOSTS_ERROR:
    fprintf(stderr, "Error %s", ssh_get_error(session));
    ssh_clean_pubkey_hash(&public_key_hash);
    return -1;
  }

  ssh_clean_pubkey_hash(&public_key_hash);
  return 0;
}


int authenticate_public_key(ssh_session session) {
  int rc;

  ssh_key public_key, private_key;
  char *homedir = getenv("HOME");
  char *public_key_path = "/.ssh/id_rsa.pub";
  char *private_key_path = "/.ssh/id_rsa";
  char *full_key_path;

  full_key_path = malloc(strlen(homedir) + strlen(public_key_path) + 2);
  memset(full_key_path, 0, strlen(homedir) + strlen(public_key_path) + 2);
  strcpy(full_key_path, homedir);
  strcat(full_key_path, public_key_path);

  rc = ssh_pki_import_pubkey_file(full_key_path, &public_key);
  if (rc != SSH_OK) {
    fprintf(stderr, "Error %s\n", strerror(errno));
    ssh_key_free(public_key);
    return -1;
  }

  memset(full_key_path, 0, strlen(homedir) + strlen(public_key_path) + 2);
  strcpy(full_key_path, homedir);
  strcat(full_key_path, private_key_path);

  rc = ssh_pki_import_privkey_file(full_key_path, NULL, NULL, NULL,
                                   &private_key);
  if (rc != SSH_OK) {
    fprintf(stderr, "Error %s\n", strerror(errno));
    free(full_key_path);
    ssh_key_free(public_key);
    ssh_key_free(private_key);
    return -1;
  }

  free(full_key_path);

  rc = ssh_userauth_publickey(session, NULL, private_key);
  if (rc != SSH_AUTH_SUCCESS) {
    fprintf(stderr, "Error %s\n", strerror(errno));
    ssh_key_free(public_key);
    ssh_key_free(private_key);
    return -1;
  }

  ssh_key_free(public_key);
  ssh_key_free(private_key);
  return 0;
}