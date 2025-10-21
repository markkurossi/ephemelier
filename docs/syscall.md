# System Call Interface

## Process Management

 - exit(arg0:exitValue) => process terminates
 - spawn(argBuf:name, arg1:nameLen) => pid
 - wait(arg0:pid) => exitValue
 - yield(arg0:preserveFlag) => 0 / preserved values
 - getpid() => pid

## File Descriptors and I/O

 - peek()
 - read(arg0:fd, arg1:size) => size, buf
 - skip()
 - write(arg0:fd, argBuf:data, arg1:size) => size
 - open()
 - close()

## Cryptography Functions

 - getrandom(arg0:size) => size, data
 - createkey(arg0:typeSize, argBuf:name, arg1:size) => fd

## Ports

 - getport(arg0:pid) => fd
 - getport(argBuf:name, arg1:size) => fd
 - createport(name, flags) => fd
 - createmsg(arg0:fd) => size, keyshare+nonce | keyshare
 - sendport(fd, fd)
 - recvport(fd) => fd
