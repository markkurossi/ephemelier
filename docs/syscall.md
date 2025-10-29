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
 - dial(argbuf:address, arg1:size) => fd
 - listen(argbuf:address, arg1:size) => fd
 - accept(arg0:fd) => fd

## Cryptography Functions

 - getrandom(arg0:size) => size, data
 - tlsserver(arg0:fd, arg1:serverKey) => fd
 - tlsclient(arg0:fd, [arg1:clientKey]) => fd
 - createkey(arg0:typeSize, argBuf:name, arg1:nameSize) => fd
 - sign(arg0:fd, argBuf:data, arg1:size) => size, signature

## Ports

 - getport(arg0:pid) => fd
 - getport(argBuf:name, arg1:size) => fd
 - createport(name, flags) => fd
 - createmsg(arg0:fd) => size, keyshare+nonce | keyshare
 - sendport(fd, fd)
 - recvport(fd) => fd
