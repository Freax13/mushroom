# Example

This binary serves as an example for the init process of a workload.

It unpacks a gzip'ed tar archive into the root directory and executes the binary at `/bin/init`. 

The Dockerfile in this directory can be used to generated such a tar archive containing the gcc compiler.
```shell
$ docker build --output type=tar,dest=gcc.tar .
...
$ gzip gcc.tar -f
$ cd ..
$ cargo make --profile production build-init
```

This can be used to compile a single file using gcc:
```shell
freax13@workstation:~/mushroom/host$ cargo make --profile production run run --init ../tee/target/x86_64-unknown-linux-musl/release/init --input ../tee/init/hello-world.c --output output.bin --attestation-report report.bin
[...]
2023-07-07T21:49:19.914729Z  INFO mushroom: launched num_launch_pages=16102 num_data_pages=16100 total_launch_duration=16.411316899s
2023-07-07T21:49:21.832970Z  INFO mushroom: finished
```
