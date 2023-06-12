#define MAX_SYSCALL_NR 1024
extern int continue_mask[];
extern int deny_mask[];

struct seccomp_notification_context {
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    int notifyfd;
};

int handle_openat(struct seccomp_notif *req, struct seccomp_notif_resp *resp, int notifyfd);
int handle_default(struct seccomp_notif *req, struct seccomp_notif_resp *resp, int notifyfd);
