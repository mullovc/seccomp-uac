#include <errno.h>
#include <linux/audit.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <seccomp.h>
#include <libnotify/notify.h>
#include "monitor.h"
#include "sendfd.h"
#include "syscall_handlers.h"

int handle_syscall(struct seccomp_notif *req, struct seccomp_notif_resp *resp, int notifyfd) {
    switch (req->data.nr) {
        case SCMP_SYS(openat):
        case SCMP_SYS(open):
            return handle_openat(req, resp, notifyfd);
        default:
            return handle_default(req, resp, notifyfd);
    }
}

void *run_gmainloop(void *) {
    GMainLoop *loop;
    loop = g_main_loop_new(nullptr, FALSE);
    g_main_loop_run(loop);
    return NULL;
}

int install_monitor(int sockfd, int pid) {
    int notifyfd = recvfd(sockfd);

    pthread_t tid;
    pthread_create(&tid, NULL, run_gmainloop, NULL);

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
            seccomp_notify_respond(notifyfd, resp);
            seccomp_notify_free(req, resp);
        }
        else if (deny_mask[nr]) {
            resp->error = -EPERM;
            resp->flags = 0;
            seccomp_notify_respond(notifyfd, resp);
            seccomp_notify_free(req, resp);
        }
        else {
            // slow path
            if (handle_syscall(req, resp, notifyfd) == -1) {
                // EPERM in case of exception
                resp->error = -EPERM;
                resp->flags = 0;
                seccomp_notify_respond(notifyfd, resp);
                seccomp_notify_free(req, resp);
            }
        }
    }

    return 0;
}
