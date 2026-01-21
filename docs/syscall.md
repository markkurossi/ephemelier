# System Call Interface

## Process Management

 - exit(arg0:exitValue) => process terminates
 - spawn(argBuf:name, arg1:nameLen) => pid
 - wait(arg0:pid) => exitValue
 - continue() => 0, nil, 0                         ; continue with zero values
 - yield() => arg0, argBuf, arg1                   ; continue with old values
 - next(arg0, argBuf, arg1) => arg0, argBuf, arg1  ; continue with new values
 - getpid() => pid
 - chroot(argBuf:path, arg1:pathLen) => arg0:errno

## File Descriptors and I/O

 - peek()
 - read(arg0:fd, arg1:size) => arg0:size, argBuf:data
 - skip()
 - write(arg0:fd, argBuf:data, arg1:size) => arg0:size
 - open(argBuf:path, arg1:pathLen) => arg0:fd, argBuf:fileInfo
 - close(arg0:fd) => errno
 - dial(argbuf:address, arg1:size) => arg0:fd
 - listen(argbuf:address, arg1:size) => arg0:fd
 - accept(arg0:fd) => arg0:fd

## Cryptography Functions

 - getrandom(arg0:size) => size, data
 - tlsserver(arg0:fd, arg1:serverKey) => fd
 - tlsclient(arg0:fd, [arg1:clientKey]) => fd
 - tlshs(arg0:fd, argBuf:payload, arg1:HSType) => HSType, Data
 - tlsstatus(arg0:fd, arg1:status) => errno
 - createkey(arg0:typeSize, argBuf:name, arg1:nameSize) => fd
 - openkey(argBuf:name, arg1:nameSize) => fd
 - sign(arg0:fd, argBuf:data, arg1:size) => size, signature

## Ports

 - getport(arg0:pid) => fd
 - getport(argBuf:name, arg1:size) => fd
 - createport(name, flags) => fd
 - createmsg(arg0:fd) => size, keyshare+nonce | keyshare
 - sendport(fd, fd)
 - recvport(fd) => fd
