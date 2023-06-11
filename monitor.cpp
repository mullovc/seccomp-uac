#define _GNU_SOURCE
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
#include "monitor.h"
#include "sendfd.h"

#ifndef FORBIDDEN_SUBSTRING
#define FORBIDDEN_SUBSTRING "passwd"
#endif

int handle_syscall(struct seccomp_notif *req, struct seccomp_notif_resp *resp, int notifyfd) {
    switch (req->data.nr) {
        case SCMP_SYS(openat):
        case SCMP_SYS(open):
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
                // TODO add errorhandling
                int targetFd;
                int fd = openat(dirfd, path, flags, mode);

                struct seccomp_notif_addfd addfd;
                addfd.id = req->id; /* Cookie from SECCOMP_IOCTL_NOTIF_RECV */
                addfd.srcfd = fd;
                addfd.newfd = 0;
                addfd.flags = 0;
                addfd.newfd_flags = O_CLOEXEC;

                targetFd = ioctl(notifyfd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);

                close(fd);          /* No longer needed in supervisor */

                resp->error = 0;        /* "Success" */
                resp->val = targetFd;
                resp->flags = 0;
            }

            break;
        default:
            resp->error = -EPERM;
            break;
    }

    return 0;
}

int install_monitor(int sockfd, int pid) {
    int notifyfd = recvfd(sockfd);

    // listen for and handle notifications
    while (1) {
        struct seccomp_notif *req;
        struct seccomp_notif_resp *resp;
        seccomp_notify_alloc(&req, &resp);
        seccomp_notify_receive(notifyfd, req);

        //// exit if child has exited
        //int wstatus;
        //waitpid(0, &wstatus, WNOHANG);
        //if (WIFEXITED(wstatus)) {
        //    printf("child exited\n");
        //    break;
        //}

#ifdef DEBUG
        printf("received %d\n", req->data.nr);
#endif

        resp->id = req->id;

        // EPERM in case of exception?
        if (handle_syscall(req, resp, notifyfd) == -1) {
            //continue;
            resp->error = -EPERM;
            resp->flags = 0;
        }

        seccomp_notify_respond(notifyfd, resp);
        seccomp_notify_free(req, resp);
    }

    return 0;
}
