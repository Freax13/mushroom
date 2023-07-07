# Example

This binary serves as an example for the init process of a workload.

It unpacks a gzip'ed tar archive into the root directory and executes the binary at `/bin/init`. 

The Dockerfile in this directory can be used to generated such a tar archive containing the gcc compiler.
```shell
$ sudo docker build -t gcc .
...
$ sudo docker run gcc
$ sudo docker ps -a
CONTAINER ID   IMAGE                                      COMMAND                  CREATED          STATUS                     PORTS     NAMES
9771c15577b1   gcc                                        "/bin/sh"                6 seconds ago    Exited (0) 5 seconds ago             bold_leakey
$ sudo docker export 9771c15577b1 -o gcc.tar
$ sudo chown freax13 gcc.tar 
$ gzip gcc.tar -f
```

This can be used to compile a single file using gcc:
```shell
freax13@workstation:~/mushroom/host$ cargo make --profile production run run --input ../tee/init/test.c --output output.bin --attestation-report report.bin
[...]
2023-07-07T21:49:19.914729Z  INFO mushroom: launched num_launch_pages=16102 num_data_pages=16100 total_launch_duration=16.411316899s
2023-07-07T21:49:21.832970Z  INFO mushroom: finished
```