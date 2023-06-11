#include <errno.h>
#include <seccomp.h>
#include <linux/unistd.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>
#include "sandbox.h"
#include "sendfd.h"

int apply_rules(scmp_filter_ctx ctx) {
    //if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(1), SCMP_SYS(mount), 0)) {
    //    perror("seccomp_rule_add");
    //    return 1;
    //}
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);

    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unshare), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(openat2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open_by_handle_at), 0);
    seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 0);

    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(link), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(symlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(linkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(symlinkat), 0);

    // prevent notification bypass through registration of higher precedence filters
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(seccomp), 0);

    return 0;
}

int init_sandbox(int sockfd) {
    scmp_filter_ctx ctx;
    // TODO error handling
    ctx = seccomp_init(SCMP_ACT_NOTIFY);
    // TODO error handling
    apply_rules(ctx);

    if (seccomp_load(ctx)) {
        perror("seccomp_load");
        return 1;
    }

    int notifyfd;
    // TODO error handling
    notifyfd = seccomp_notify_fd(ctx);

    // TODO error handling
    sendfd(sockfd, notifyfd);
#ifdef DEBUG
    printf("notify fd: %d\n", notifyfd);
#endif
    close(notifyfd);

    return 0;
}

int run_sandbox() {
    // spawn shell
    if (execl("/bin/bash", "/bin/bash",NULL)) {
        perror("execl");
        return 1;
    }
    return 0;
}
