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
            return UAC_ALLOW_ONCE;
        default:
            //resp->error = -EPERM;
            resp->error = 0;
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            return UAC_ALLOW;
    }
}

int install_monitor(int sockfd, int pid) {
    int notifyfd = recvfd(sockfd);
    int continue_mask[MAX_SYSCALL_NR] = { 0 };
    int deny_mask[MAX_SYSCALL_NR] = { 0 };

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

        int nr = req->data.nr;
#ifdef DEBUG
        printf("received %d\n", nr);
#endif

        resp->id = req->id;

        // fast path
        if (continue_mask[nr]) {
            resp->error = 0;
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        }
        else if (deny_mask[nr]) {
            resp->error = -EPERM;
            resp->flags = 0;
        }
        else {
            // slow path
            int decision;
            if ((decision = handle_syscall(req, resp, notifyfd)) == -1) {
                // EPERM in case of exception?
                //continue;
                resp->error = -EPERM;
                resp->flags = 0;
            }

            if (decision == UAC_ALLOW) {
                continue_mask[nr] = 1;
            }
            else if (decision == UAC_DENY) {
                deny_mask[nr] = 1;
            }
        }

        seccomp_notify_respond(notifyfd, resp);
        seccomp_notify_free(req, resp);
    }

    return 0;
}
