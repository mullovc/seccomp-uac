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
#include <sys/wait.h>
#include <fcntl.h>
#include "monitor.h"
#include "sendfd.h"

#ifndef FORBIDDEN_SUBSTRING
#define FORBIDDEN_SUBSTRING "passwd"
#endif

int handle_syscall(struct seccomp_notif *req, struct seccomp_notif_resp *resp) {
    switch (req->data.nr) {
        case SCMP_SYS(openat):
        case SCMP_SYS(open):
            uint64_t addr;
            int memfd;
            char *mempath;
            char buf[4096];

            if (req->data.nr == SCMP_SYS(open)) {
                addr = req->data.args[0];
            }
            else { // req->data.nr == SCMP_SYS(openat)
                addr = req->data.args[1];
            }

            asprintf(&mempath, "/proc/%d/mem", req->pid);
            memfd = open(mempath, O_RDONLY);
            free(mempath);
            if (memfd < 0) {
                perror("open");
                return -1;
            }
            lseek(memfd, addr, SEEK_SET);
            // missing null byte?
            if (read(memfd, buf, 4096) == -1) {
                perror("read");
                close(memfd);
                return -1;
            }
            close(memfd);

#ifdef DEBUG
            printf("read: %s\n", buf);
#endif
            if (strstr(buf, FORBIDDEN_SUBSTRING) != NULL) {
                printf("Tried to access forbidden file!\n");
                resp->error = -EPERM;
            }
            else {
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            }
            break;
        default:
            resp->error = -EPERM;
            break;
    }

    return 0;
}

int install_monitor(int sockfd, int pid) {
    int fd = recvfd(sockfd);

    // listen for and handle notifications
    while (1) {
        struct seccomp_notif *req;
        struct seccomp_notif_resp *resp;
        seccomp_notify_alloc(&req, &resp);
        seccomp_notify_receive(fd, req);

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
#ifdef DEBUG2
        printf("dirfd: %d\npath: 0x%llx\nflags: %x\nmode: %x\n",
               (int)req->data.args[0],
               req->data.args[1],
               (int)req->data.args[2],
               (int)req->data.args[3]);
#endif

        resp->id = req->id;

        // EPERM in case of exception?
        if (handle_syscall(req, resp) == -1) {
            //continue;
            resp->error = -EPERM;
            resp->flags = 0;
        }

        seccomp_notify_respond(fd, resp);
        seccomp_notify_free(req, resp);
    }
    return fd;
}
