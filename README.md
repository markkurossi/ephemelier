# The Ephemelier Operating System

The Ephemelier operating system is an MPC virtual machine and
execution environment. It executes programs in the "MPC space"
i.e. the Ephemelier nodes can't access the memory or the computation
of the programs.

## Example

The following commands are run in the `cmd/ephemelier` directory.

First, start the evaluator node:

``` shell
$ ./ephemelier -e -ktrace
Ephemelier Evaluator Node
Listening for MPC connections at :9000
```

Next, start the garbler node:

``` shell
./ephemelier -ktrace -console
Ephemelier Garbler Node
Console running at :2323
```

Finally, connect to the console port via telnet:

``` shell
$ telnet localhost 2323
Trying ::1...
Connected to localhost.
Escape character is '^]'.
Ephemelier v0.0 - Copyright (c) 2025 Markku Rossi
esh $ Ephemelier
Hello, Ephemelier!
esh $ exit
Connection closed by foreign host.
```

## TODO

 - [ ] Shell with command launch & wait
 - [ ] Circuit stats in streaming mode (INFO)
 - [ ] Optimize input setting (direct vs. via strings)
