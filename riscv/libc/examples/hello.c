/*
 * Copyright (c) 2026 Markku Rossi
 *
 * All rights reserved.
 */


#include <unistd.h>

int
main()
{
  const char msg[] = "Hello, RISC-V!\n";

  write(1, msg, sizeof(msg) - 1);

  return 0;
}
