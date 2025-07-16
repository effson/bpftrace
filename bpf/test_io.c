#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define FILEPATH "/home/jeff/big_read_test.dat"

void uflush(void) {
    printf("========================userspace flush called=============================\n");
}

void uopen(void) {
    printf("========================userspace open called=============================\n");
}

void ucreate(void) {
    printf("========================userspace ucreate called=============================\n");
}

void uread(void) {
    printf("========================userspace read called=============================\n");
}

void uwrite(void) {
    printf("========================userspace write called=============================\n");
}

int main() {
    ucreate();
    int fd = creat(FILEPATH, 0644);
    char buf[4096];
    for (int i = 0; i < sizeof(buf); i++) buf[i] = 'B';
    uwrite();
    write(fd, buf, sizeof(buf));
    uflush();
    fsync(fd);
    close(fd);

    system("sync; echo 3 > /proc/sys/vm/drop_caches");

    // 重新打开并读取
    uopen();
    fd = open(FILEPATH, O_RDONLY);
    uread();
    while (read(fd, buf, sizeof(buf)) > 0) {
        // 模拟读取
    }
    close(fd);
    return 0;
}
