# External Tests

mushroom's goal is to run Linux programs, so it only makes sense that we test mushroom with external third-party programs.
The `run-external-test` make target can be used to build and run the tests for a nix package in mushroom.

Example: `make run-external-test PACKAGE=coreutils TIME_BACKEND=real`

`run-external-test` will build a docker image that executes a nix build and export it to as a tar archive.
The init binary will take this tar archive as the input, unpack it, and execute it.
