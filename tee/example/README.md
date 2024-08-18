# Example

This binary serves as an example for the init process of a workload.

It unpacks a gzip'ed tar archive into the root directory and executes the binary at `/bin/init`. 

This example init binary can be used to compile a hello-world.c using gcc:
```shell
freax13@workstation:~/mushroom$ make PROFILE=release run-example
[...]
2023-07-07T21:49:19.914729Z  INFO mushroom: launched num_launch_pages=16102 num_data_pages=16100 total_launch_duration=16.411316899s
2023-07-07T21:49:21.832970Z  INFO mushroom: finished
```
