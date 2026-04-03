/*
 * Copyright (c) 2026 Markku Rossi
 *
 * All rights reserved.
 */

#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>

// RISC-V Linux syscall numbers (subset)
#define SYS_read    63
#define SYS_write   64
#define SYS_exit    93

static inline long
syscall0(long n)
{
  register long a7 asm("a7") = n;
  register long a0 asm("a0");
  asm volatile ("ecall"
                : "=r"(a0)
                : "r"(a7)
                : "memory");
  return a0;
}

static inline long
syscall1(long n, long a)
{
  register long a7 asm("a7") = n;
  register long a0 asm("a0") = a;
  asm volatile ("ecall"
                : "+r"(a0)
                : "r"(a7)
                : "memory");
  return a0;
}

static inline long
syscall3(long n, long a, long b, long c)
{
  register long a7 asm("a7") = n;
  register long a0 asm("a0") = a;
  register long a1 asm("a1") = b;
  register long a2 asm("a2") = c;

  asm volatile ("ecall"
                : "+r"(a0)
                : "r"(a7), "r"(a1), "r"(a2)
                : "memory");

  return a0;
}

#endif /* not SYSCALL_H */
