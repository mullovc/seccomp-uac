#include <errno.h>
#include <linux/audit.h>
#include <seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>


int sendfd(int sockfd, int fd) {
    // send notification file descriptor
    // (just a bunch of boilerplate code blindly copied from https://stackoverflow.com/a/28005250)
    struct msghdr msg = { 0 };
    char buf[CMSG_SPACE(sizeof(fd))];
    memset(buf, '\0', sizeof(buf));
    //struct iovec io = { .iov_base = "ABC", .iov_len = 3 };
    struct iovec io = { .iov_base = (void*)"ABC", .iov_len = 3 };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    *((int *) CMSG_DATA(cmsg)) = fd;
    msg.msg_controllen = CMSG_SPACE(sizeof(fd));
    if (sendmsg(sockfd, &msg, 0) < 0) {
        perror("Failed to send message\n");
        return 1;
    }
    return 0;
}

int recvfd(int sockfd) {
    // receive notification file descriptor
    // (just a bunch of boilerplate code blindly copied from https://stackoverflow.com/a/28005250)
    struct msghdr msg = {0};
    char m_buffer[256];
    struct iovec io = { .iov_base = m_buffer, .iov_len = sizeof(m_buffer) };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    char c_buffer[256];
    msg.msg_control = c_buffer;
    msg.msg_controllen = sizeof(c_buffer);
    if (recvmsg(sockfd, &msg, 0) < 0) {
        perror("Failed to receive message\n");
        return 1;
    }
    struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
    unsigned char * data = CMSG_DATA(cmsg);

#ifdef DEBUG
    printf("About to extract fd\n");
#endif
    int fd = *((int*) data);
#ifdef DEBUG
    printf("Extracted fd %d\n", fd);
#endif

    return fd;
}
