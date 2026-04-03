/*
 * Copyright (c) 2026 Markku Rossi
 *
 * All rights reserved.
 */

#include "syscall.h"
#include "unistd.h"

ssize_t
read(int fd, void *buf, size_t count)
{
  return syscall3(SYS_read, fd, (long) buf, count);
}

ssize_t
write(int fd, const void *buf, size_t count)
{
    return syscall3(SYS_write, fd, (long) buf, count);
}

void
_exit(int status)
{
  syscall1(SYS_exit, status);

  // Should never return.
  while (1)
    ;
}
