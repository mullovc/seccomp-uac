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
#include <libnotify/notify.h>
#include "syscall_handlers.h"


#ifndef FORBIDDEN_SUBSTRING
#define FORBIDDEN_SUBSTRING "passwd"
#endif

int continue_mask[MAX_SYSCALL_NR] = { 0 };
int deny_mask[MAX_SYSCALL_NR] = { 0 };


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
    }
    else {
        int targetFd;
        int fd;

        if ((fd = openat(dirfd, path, flags, mode)) == -1) {
            resp->val = fd;
            resp->error = -errno;
            resp->flags = 0;
            seccomp_notify_respond(notifyfd, resp);
            seccomp_notify_free(req, resp);
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
    seccomp_notify_respond(notifyfd, resp);
    seccomp_notify_free(req, resp);

    return 0;
}

void callback_default(NotifyNotification* n, char* action, gpointer user_data) {
    struct seccomp_notification_context *ctx = (struct seccomp_notification_context *)user_data;
    struct seccomp_notif *req = ctx->req;
    struct seccomp_notif_resp *resp = ctx->resp;
    int notifyfd = ctx->notifyfd;

    printf("action: %s\n", action);

    resp->error = 0;
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    seccomp_notify_respond(notifyfd, resp);
    seccomp_notify_free(req, resp);
    free(ctx);

    continue_mask[req->data.nr] = 1;
}

int handle_default(struct seccomp_notif *req, struct seccomp_notif_resp *resp, int notifyfd) {
    //GError *error = NULL;
    notify_init("Basics");
    char *syscall_name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, req->data.nr);
    NotifyNotification* n = notify_notification_new("UAC", syscall_name, NULL);
    free(syscall_name);

    struct seccomp_notification_context *ctx;
    ctx = (struct seccomp_notification_context *)malloc(sizeof(seccomp_notification_context));
    ctx->req = req;
    ctx->resp = resp;
    ctx->notifyfd = notifyfd;

    notify_notification_add_action(n,
                                   "action_yes",
                                   "Allow",
                                   NOTIFY_ACTION_CALLBACK(callback_default),
                                   ctx,
                                   NULL);
    notify_notification_add_action(n,
                                   "action_no",
                                   "Deny",
                                   NOTIFY_ACTION_CALLBACK(callback_default),
                                   ctx,
                                   NULL);

    notify_notification_set_timeout(n, 10000);
    if (!notify_notification_show(n, 0)) {
        perror("notify_notification_show");
        return -1;
    }
    return 0;
}
