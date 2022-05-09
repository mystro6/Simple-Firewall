 


#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
 
#define NETLINK_USER 17
 
#define MAX_PAYLOAD 1024 /* maximum payload size*/

void print_usage(void);
int check_ip(char *ip);

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;
 
int main(int argc, char **argv) {

    char message[50];
    memset(&message,0,sizeof(message));

   
    if(argc == 2)
    {
        printf("%s\n",argv[1] );
        if(!(strcmp(argv[1], "-h")))
        {
            print_usage();
        }
    }

    else if(argc > 2)
    {
        if(!strcmp(argv[1], "-p"))
        {
            if(atoi(argv[2]) >= 0 && atoi(argv[2]) < 65536)
            {
                if(!(strcmp(argv[3], "drop") && strcmp(argv[3], "accept")))
                {
                    strcpy(message, argv[1]);
                    strcat(message, " ");
                    strcat(message, argv[2]);
                    strcat(message, " ");
                    strcat(message, argv[3]);
                    printf("Message generated:%s\n",message);
                }
            }
        }
        else if(!strcmp(argv[1], "-ip"))
        {
            if(check_ip(argv[2]))
            {
                if(!(strcmp(argv[3], "drop") && strcmp(argv[3], "accept")))
                {
                    strcpy(message, argv[1]);
                    strcat(message, " ");
                    strcat(message, argv[2]);
                    strcat(message, " ");
                    strcat(message, argv[3]);
                    printf("Message generated:%s\n",message);
                }
            }
        }
    }

    //TODO: if message is not generated exit(else causes)

    sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if(sock_fd<0)
        return -1;
 
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */
 
    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
 
    memset(&dest_addr, 0, sizeof(dest_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */
 
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
 
    strcpy(NLMSG_DATA(nlh), message);
 
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
 
    printf("Sending message to kernel\n");
    sendmsg(sock_fd,&msg,0);
 
    //printf("Waiting for message from kernel\n");
 
    /* Read message from kernel */
    // recvmsg(sock_fd, &msg, 0);
    // printf("Received message payload: %s\n", (char *)NLMSG_DATA(nlh));
    close(sock_fd);
    return 0;
}

void print_usage(void)
{
    printf("Usage:\n");
            printf("./user_prog -p 55 drop\n");
            printf("./user_prog -p 40 accept\n");
            printf("./user_prog -ip 10.41.30.20 drop\n");
            printf("./user_prog -ip 10.41.30.20 accept\n");
            printf("./user_prog -h\n");
            printf("./user_prog -default (block all ports except 80)\n");
}

int check_ip(char *ip)
{
    unsigned long addr = inet_addr(ip);

    if (-1 == addr) {

        return 0;
    }

    return 1;
}