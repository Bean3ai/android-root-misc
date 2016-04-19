#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

struct test_struct{
    unsigned short		skc_family;//--------------2Byte
    volatile unsigned char	skc_state;//-----------1Byte
    unsigned char		skc_reuse:4;//
    unsigned char		skc_reuseport:4;//
    int			skc_bound_dev_if;//----------------4Byte
};

int main(int argc, char **argv){
    printf("sizeof=%d\n", sizeof(struct test_struct));
    printf("O_NONBLOCK=%x\n", O_NONBLOCK);
    return 0;
}