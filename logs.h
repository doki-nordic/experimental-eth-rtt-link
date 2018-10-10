#ifndef LOGS_H
#define LOGS_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>


#define LOG_NONE  0
#define LOG_ERROR 1
#define LOG_INFO  2
#define LOG_DEBUG 3
#define LOG_NRFJPROG 4


#define MY_FATAL(text, ...) do { fprintf(stderr, "%s:%d: fatal: " text "\n", __FILE__, __LINE__, ##__VA_ARGS__); exit(100); } while (0);
#define MY_ERROR(text, ...) do { int __tmp_errno = errno; fprintf(stderr, "%s:%d: error: " text "\n", __FILE__, __LINE__, ##__VA_ARGS__); errno = __tmp_errno; } while (0);
#define MY_INFO(text, ...) fprintf(stdout, text "\n", ##__VA_ARGS__)

#endif
