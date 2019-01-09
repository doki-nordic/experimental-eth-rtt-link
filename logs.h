/*
 * Copyright (c) 2019 Nordic Semiconductor
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef LOGS_H
#define LOGS_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "options.h"

#define LOG_NONE  0
#define LOG_ERROR 1
#define LOG_INFO  2
#define LOG_DEBUG 3
#define LOG_NRFJPROG 4

#define OPTIONS_EXIT_CODE 1
#define RECOVERABLE_EXIT_CODE 2
#define UNRECOVERABLE_EXIT_CODE 3
#define TERMINATION_EXIT_CODE 4

#define O_FATAL(text, ...) do { fprintf(stderr, "%s:%d: fatal: " text "\n", __FILE__, __LINE__, ##__VA_ARGS__); exit(OPTIONS_EXIT_CODE); } while (0)
#define R_FATAL(text, ...) do { if (options.verbose >= LOG_ERROR) fprintf(stderr, "%s:%d: fatal: " text "\n", __FILE__, __LINE__, ##__VA_ARGS__); exit(RECOVERABLE_EXIT_CODE); } while (0)
#define U_FATAL(text, ...) do { if (options.verbose >= LOG_ERROR) fprintf(stderr, "%s:%d: fatal: " text "\n", __FILE__, __LINE__, ##__VA_ARGS__); exit(UNRECOVERABLE_EXIT_CODE); } while (0)

#define PRINT_ERROR(text, ...) do { if (options.verbose >= LOG_ERROR) fprintf(stderr, "%s:%d: error: " text "\n", __FILE__, __LINE__, ##__VA_ARGS__); } while (0)
#define PRINT_INFO(text, ...) do { if (options.verbose >= LOG_INFO) fprintf(stderr, "%s:%d: info: " text "\n", __FILE__, __LINE__, ##__VA_ARGS__); } while (0)
#define PRINT_DEBUG(text, ...) do { if (options.verbose >= LOG_DEBUG) fprintf(stderr, "%s:%d: debug: " text "\n", __FILE__, __LINE__, ##__VA_ARGS__); } while (0)
#define PRINT_NRFJPROG(text, ...) do { if (options.verbose >= LOG_NRFJPROG) fprintf(stderr, "nrfjprog: " text "\n", ##__VA_ARGS__); } while (0)

#define R_ERRNO_FATAL(text, ...) do { if (options.verbose >= LOG_ERROR) fprintf(stderr, "%s:%d: fatal: " text "\n    errno %d: %s\n", __FILE__, __LINE__, ##__VA_ARGS__, errno, strerror(errno)); exit(RECOVERABLE_EXIT_CODE); } while (0)
#define U_ERRNO_FATAL(text, ...) do { if (options.verbose >= LOG_ERROR) fprintf(stderr, "%s:%d: fatal: " text "\n    errno %d: %s\n", __FILE__, __LINE__, ##__VA_ARGS__, errno, strerror(errno)); exit(UNRECOVERABLE_EXIT_CODE); } while (0)
#define PRINT_ERRNO_ERROR(text, ...) do { if (options.verbose >= LOG_ERROR) fprintf(stderr, "%s:%d: error: " text "\n    errno %d: %s\n", __FILE__, __LINE__, ##__VA_ARGS__, errno, strerror(errno)); } while (0)
#define PRINT_ERRNO_INFO(text, ...) do { if (options.verbose >= LOG_INFO) fprintf(stderr, "%s:%d: info: " text "\n    errno %d: %s\n", __FILE__, __LINE__, ##__VA_ARGS__, errno, strerror(errno)); } while (0)
#define PRINT_ERRNO_DEBUG(text, ...) do { if (options.verbose >= LOG_DEBUG) fprintf(stderr, "%s:%d: debug: " text "\n    errno %d: %s\n", __FILE__, __LINE__, ##__VA_ARGS__, errno, strerror(errno)); } while (0)

#endif
