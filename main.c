#include "include/ssh.h"
#include "include/scp.h"

int main() {
  ssh_session new_ssh_session;
  ssh_scp scp;

  char *hostname = "ec2-35-86-123-210.us-west-2.compute.amazonaws.com";
  int port = 22;
  char *username = "mariamfahmy";
  int rc;

  new_ssh_session = ssh_new();
  if (new_ssh_session == NULL) {
    exit(-1);
  }

  ssh_options_set(new_ssh_session, SSH_OPTIONS_USER, username);
  ssh_options_set(new_ssh_session, SSH_OPTIONS_HOST, hostname);
  ssh_options_set(new_ssh_session, SSH_OPTIONS_PORT, &port);

  // Connecting to EC2 instance.
  rc = ssh_connect(new_ssh_session);
  if (rc != SSH_OK) {
    fprintf(stderr, "Error connecting to %s: %s\n", hostname,
            ssh_get_error(new_ssh_session));
    exit(-1);
  }

  // Verify server's identity.
  if (verify_knownhosts(new_ssh_session) < 0) {
    printf("verify known hosts failed\n");
    ssh_disconnect(new_ssh_session);
    ssh_free(new_ssh_session);
    exit(-1);
  }

  // Authenticating with public keys.
  if (authenticate_public_key(new_ssh_session) < 0) {
    ssh_disconnect(new_ssh_session);
    ssh_free(new_ssh_session);
    exit(-1);
  }

  // Opening SCP session with write mode.
  scp = ssh_scp_new(new_ssh_session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, ".");
  if (scp == NULL) {
    fprintf(stderr, "Error allocating scp session: %s\n",
            ssh_get_error(new_ssh_session));
    exit(-1);
  }

  rc = ssh_scp_init(scp);
  if (rc != SSH_OK) {
    fprintf(stderr, "Error initializing scp session: %s\n",
            ssh_get_error(new_ssh_session));
    ssh_scp_free(scp);
  }

  scp_send_directory(new_ssh_session, scp);

  ssh_scp_close(scp);
  ssh_scp_free(scp);

  ssh_disconnect(new_ssh_session);
  ssh_free(new_ssh_session);
  exit(0);
}
