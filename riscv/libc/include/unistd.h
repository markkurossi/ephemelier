/*
 * Copyright (c) 2026 Markku Rossi
 *
 * All rights reserved.
 */

#ifndef UNISTD_H
#define UNISTD_H

#include <stddef.h>

ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
void _exit(int status);

#endif /* not UNISTD_H */
