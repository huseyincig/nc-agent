#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int main(void) {
  struct ucred cred;
  socklen_t len = sizeof(cred);
  memset(&cred, 0, sizeof(cred));
  if (getsockopt(3, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
    fprintf(stderr, "PEERCRED_FAILED:%d\n", errno);
    return 2;
  }
  if (len != sizeof(cred) || cred.pid <= 0) {
    fprintf(stderr, "PEERCRED_INVALID\n");
    return 3;
  }
  printf("{\"pid\":%ld,\"uid\":%lu,\"gid\":%lu}\n",
    (long)cred.pid, (unsigned long)cred.uid, (unsigned long)cred.gid);
  return 0;
}
