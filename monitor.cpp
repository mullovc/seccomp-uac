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
#include "syscall_handlers.h"

int handle_syscall(struct seccomp_notif *req, struct seccomp_notif_resp *resp, int notifyfd) {
    switch (req->data.nr) {
        case SCMP_SYS(openat):
        case SCMP_SYS(open):
            handle_openat(req, resp, notifyfd);
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
