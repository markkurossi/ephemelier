# System Call Interface

## Ports

Port functions:

 - getport(pid) => fd
 - getport(name) => fd
 - createport(name, flags) => fd
 - createmsg(fd) => keyshare|nonce, keyshare
 - write(fd, data, len)
 - read(fd, len) => data
 - close(fd)
 - sendport(fd, fd)
 - recvport(fd) => fd
