#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "sockopt.h"

#define USAGE "./sockopt get \n"  \
              "./sockopt set buffer \n"

#define BUFFER_LEN_MAX 1024
static char buffer[BUFFER_LEN_MAX];

static int getsockopt_handler(void)
{
    int fd, ret, size;
    
    size = sizeof(buffer);
    memset(buffer, '\0', size);
    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if(fd == -1) 
    {
        printf("socket error, errno : %d\n", errno);
        return -1;
    }
    
    ret = getsockopt(fd, IPPROTO_IP, SOCKOPT_GET_BUFFER, buffer, &size);
    if (ret == -1)
    {
        printf("getsockopt fail, errno : %d\n", errno);
    }
    else
    {
        printf("getsockopt return buffer : %s\n", buffer);
    }
    close(fd);
    return 0;
}

static int setsockopt_handler(char *arg)
{
    int fd, ret, cpy_len;
    unsigned int size;
    
    size = sizeof(buffer);
    cpy_len = size > strlen(arg) ? strlen(arg) : size;        
    memset(buffer, '\0', size);
    memcpy(buffer, arg, cpy_len);
    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if(fd == -1) 
    {
        printf("socket error, errno : %d\n", errno);
        return -1;
    }
    
    ret = setsockopt(fd, IPPROTO_IP, SOCKOPT_SET_BUFFER, buffer, size);
    if (ret == -1)
    {
        printf("setsockopt fail, errno : %d\n", errno);
    }
    
    close(fd);
    return 0;
}

 
int main(int argc, char **argv)
{
    int index;
    int value = 9;
 
    if(argc < 2) 
    {                
        goto FAIL;
    }
 
    if(strcmp(argv[1], "get") == 0) {
        return getsockopt_handler();
    } else if(strcmp(argv[1], "set") == 0) {
        if (argc != 3)
        {
            goto FAIL;
        }
        return setsockopt_handler(argv[2]);
    } 
 
FAIL:
    printf(USAGE);
    exit(EXIT_FAILURE);
}