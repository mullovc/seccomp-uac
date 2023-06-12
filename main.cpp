#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include "monitor.h"
#include "sandbox.h"


int main(int argc, char *argv[]) {
    int sockPair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockPair) == -1) {
        perror("socketpair");
        return 1;
    }

    int pid = fork();
    if (pid > 0) { // in parent
        install_monitor(sockPair[0], pid);
    }
    else { // in child
        if (init_sandbox(sockPair[1])) {
            return 1;
        }
        if (run_sandbox()) {
            return 1;
        }
    }
    //return EXIT_SUCCESS;
    return 0;
}
