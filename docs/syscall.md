# System Call Interface

## Process Management

 - exit(arg0:exitVal) => process terminates
 - spawn(argBuf:name, arg1:nameLen) => pid
 - wait(arg0:pid) => exitVal
 - yield(arg0:preserveFlag) => 0 / preserved values
 - getpid() => pid

## File Descriptors and I/O

 - peek()
 - read()
 - skip()
 - write()
 - open()
 - close()

## Cryptography Functions

 - getrandom()

## Ports

 - getport(pid) => fd
 - getport(name) => fd
 - createport(name, flags) => fd
 - createmsg(fd) => keyshare+nonce | keyshare
 - sendport(fd, fd)
 - recvport(fd) => fd
