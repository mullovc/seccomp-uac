#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <linux/audit.h>
#include <seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "syscall_handlers.h"


#ifndef FORBIDDEN_SUBSTRING
#define FORBIDDEN_SUBSTRING "passwd"
#endif

int handle_openat(struct seccomp_notif *req, struct seccomp_notif_resp *resp, int notifyfd) {
    uint64_t addr;
    int flags;
    mode_t mode;
    int dirfd;
    int memfd;
    char *mempath;
    char path[4096];

#ifdef DEBUG2
    printf("dirfd: %d\npath: 0x%llx\nflags: %x\nmode: %x\n",
            (int)req->data.args[0],
            req->data.args[1],
            (int)req->data.args[2],
            (int)req->data.args[3]);
#endif

    if (req->data.nr == SCMP_SYS(open)) {
        dirfd = AT_FDCWD;
        addr = req->data.args[0];
        flags = req->data.args[1];
        mode = req->data.args[2];
    }
    else { // req->data.nr == SCMP_SYS(openat)
        dirfd = req->data.args[0];
        addr = req->data.args[1];
        flags = req->data.args[2];
        mode = req->data.args[3];
    }

    // extract file path from target process memory
    asprintf(&mempath, "/proc/%d/mem", req->pid);
    memfd = open(mempath, O_RDONLY);
    free(mempath);
    if (memfd < 0) {
        perror("open");
        return -1;
    }
    lseek(memfd, addr, SEEK_SET);
    // missing null byte?
    if (read(memfd, path, 4096) == -1) {
        perror("read");
        close(memfd);
        return -1;
    }
    close(memfd);

#ifdef DEBUG
    printf("read: %s\n", path);
#endif
    if (strstr(path, FORBIDDEN_SUBSTRING) != NULL) {
        printf("Tried to access forbidden file!\n");
        resp->error = -EPERM;
        return 0;
    }
    else {
        int targetFd;
        int fd;

        if ((fd = openat(dirfd, path, flags, mode)) == -1) {
            resp->val = fd;
            resp->error = -errno;
            resp->flags = 0;
            return 0;
        }

        struct seccomp_notif_addfd addfd;
        addfd.id = req->id; /* Cookie from SECCOMP_IOCTL_NOTIF_RECV */
        addfd.srcfd = fd;
        addfd.newfd = 0;
        addfd.flags = 0;
        addfd.newfd_flags = O_CLOEXEC;

        // TODO add errorhandling
        targetFd = ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);

        close(fd);          /* No longer needed in supervisor */

        resp->error = 0;        /* "Success" */
        resp->val = targetFd;
        resp->flags = 0;
    }

    return 0;
}
