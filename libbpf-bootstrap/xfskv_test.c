#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>

#define ALIGNMENT_SIZE 4096
#define FILE_NAME_SIZE 256

long long get_timestamp_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <test_directory> <num_tests> <file_size_MiB>\n", argv[0]);
        return 1;
    }

    const char *test_dir = argv[1];
    int num_tests = atoi(argv[2]);
    int file_size_mib = atoi(argv[3]);

    long value_size_bytes = (long)file_size_mib * 1024 * 1024;

    printf("Starting test with %d iterations in directory: %s\n", num_tests, test_dir);
    printf("File size per test: %d MiB\n", file_size_mib);

    char *value_data = NULL;
    if (posix_memalign((void **)&value_data, ALIGNMENT_SIZE, value_size_bytes) != 0) {
        perror("Failed to allocate aligned memory");
        return 1;
    }

    memset(value_data, 'A', value_size_bytes);

    long long total_latency = 0;
    long long max_latency = 0;
    long long min_latency = 0;
    long long *latencies = (long long*)malloc(sizeof(long long) * num_tests);

    for (int i = 0; i < num_tests; ++i) {
        char filename[FILE_NAME_SIZE];
        sprintf(filename, "%s/key_%d.bin", test_dir, i);

        long long t_start = get_timestamp_us();
        int fd = open(filename, O_WRONLY | O_CREAT | O_DIRECT, 0644);
        if (fd < 0) {
            perror("Failed to open file");
            continue; 
        }

        ssize_t bytes_written = write(fd, value_data, value_size_bytes);
        if (bytes_written != value_size_bytes) {
            perror("Failed to write data");
            close(fd);
            continue;
        }
        fsync(fd);
        close(fd);

        long long t_end = get_timestamp_us();
        long long latency = t_end - t_start;

        latencies[i] = latency;
        total_latency += latency;
        if (latency > max_latency) {
            max_latency = latency;
        }

        if (latency < min_latency) {
            min_latency = latency;
        }
    }

    printf("Number of tests: %d\n", num_tests);
    printf("Total latency: %lld us\n", total_latency);
    printf("Average latency: %lld us\n", total_latency / num_tests);
    printf("Max latency: %lld us\n", max_latency);
    printf("Min latency: %lld us\n", min_latency);

    free(value_data);
    free(latencies);    
    return 0;
}
