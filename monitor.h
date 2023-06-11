#define MAX_SYSCALL_NR 1024

#define UAC_DENY        1
#define UAC_DENY_ONCE   2
#define UAC_ALLOW       3
#define UAC_ALLOW_ONCE  4

int install_monitor(int sockfd, int pid);
