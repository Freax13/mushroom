# :mushroom: mushroom :mushroom:

Run integrity protected workloads in a hardware based Trusted Execution Environment. 

mushroom can be used to process inputs using unmodified Linux workloads. It can create and verify attestation reports proving that the output for a given input hasn't been tampered with. It tries to provide a very high level of security by aggressively cutting down on potential attack surfaces. mushroom's security is rooted in secure encrypted virtual machines based on AMD's SEV-SNP and Intel's TDX technologies. 

## Warning

mushroom is still very experimental! Chances are it can't even run most workloads yet because it doesn't implement enough of the Linux syscall interface. mushroom has not received any external security audits.

## Architecture and Core Concepts

mushroom is split up into three parts:
1. mushroom library and executable:
These implement a minimal VMM to launch the VM on a Linux host.
1. workload kernel:
This kernel runs the workloads. On AMD SEV-SNP, it runs at VMPL 1. On Intel TDX, it runs in a L2 nested VM. This kernel never directly talks to the host.
1. supervisor kernel: 
This kernel runs at VMPL 0 on AMD SEV-SNP and runs as the L1 VM on Intel TDX. It mediates between the communication between the workload kernel and the host. It handles necessary host communication such as for input and output transfer, memory hot plugging, and AP boot.

### Reduce Attack Surface

The code running in the VM has been split up into two parts, the workload kernel and the supervisor kernel, to reduce the amount security relevant code. It should be sufficient to audit the supervisor kernels as the the workload kernel should never come into contact with untrusted data.

The supervisor kernels are the only component directly talking to the host. The supervisor kernels are intentionally kept small and is hardended against exploits. On AMD SEV-SNP, it is entirely single-threaded.

The workload kernel cannot access host shared memory and even though it's in theory not impossible for it to communicate to the host through some side-channels, it should be very unlikely that the host can influence the code running in the workload kernel.

### Tell, Don't Ask

Communication between the supervisor kernel and the host has been designed in such a way that data mostly flows from the supervisor kernel to the host and not the other way around. This makes it more difficult for the host to feed the supervisor kernel invalid data that could cause a vulnerability.

### Attest All Inputs

The following data ends up in the attestation report:
1. supervisor kernel
1. workload kernel
1. init executable
1. input data

The input data is included in the attestation report to ensure that an attacker doesn't feed malicous input to the workload which exploits some vulnerability in the workload.

It should be impossible for the attacker to tamper with any of these without the attestation report changing.

There is no way for the workloads to communicate with the host, external devices or external services. The only input to the workload is the input file provided to it.

### Non-goals

The workload kernel has not been hardened against attacks from within the workload itself, only the outputs of trusted workloads and inputs should be considered trusted. 

## Example Use Cases

mushroom could be the basis of a secure remote build system: mushroom could be used to securely compile code on untrusted servers. The attestation report would prove that the compiled program really corresponds to the input source files and hasn't been backdoored or otherwise tampered with.

## Usage

KVM host support for AMD SEV-SNP has been partially upstreamed into the Linux kernel, but [additional patches](https://github.com/Freax13/linux/tree/snp-guest-req-v1b-mushroom) are needed. KVM host support for Intel TDX has not yet been upstreamed. A [tree](https://github.com/Freax13/linux/tree/mushroom-tdx) based on Intel's partitioning patches can be used.

The host folder contains cargo-make files to simplify the process of running a workload.

To execute a workload use:
```shell
freax13@workstation:~/mushroom$ make run PROFILE=release INPUT=input-file OUTPUT=output.bin ATTESTATION_REPORT=report.bin
[...]
2023-07-07T20:45:00.670741Z  INFO mushroom: launched num_launch_pages=16102 num_data_pages=16100 total_launch_duration=16.47807905s
2023-07-07T20:45:02.570740Z  INFO mushroom: finished
```
To verify the output with attestation report simply swap out the `run` subcommand with `verify`:
```shell
freax13@workstation:~/mushroom$ make verify PROFILE=release INPUT=input-file OUTPUT=output.bin ATTESTATION_REPORT=report.bin
[...]
Ok
```

See [tee/init/README.md](./tee/init/README.md) for an example workload.

# Known Issues

## Time

Securely keeping track of time inside a secure VM is difficult.
Even under Intel TDX or with AMD SEV-SNP SecureTSC enabled, the hypervisor can change the VM's perception of time e.g. by frequently pausing execution of the VM for a brief moment.

The two main requirements for a time-keeping implementation are:
1. The hypervisor should not be able to mess with the workload's perception of time.
2. The clock should be accurate.

We are not aware of any way to achieve both of these goals under AMD SEV-SNP or Intel TDX.
Instead, we implement two different "time backends" and let the user pick one of them at compile time:

1. The `fake` time backend doesn't use any of the CPU's native time-keeping facilities and meerly increments a counter by a fixed amount every time the current time is requested. This clock is completly deterministic and can't be influenced by the hypervisor, but it's also very inaccurate.
2. The `real` time backend, uses the SecureTSC SEV feature and TDX's TSC virtualization and the `rdtsc` instruction to query the current time. This clock backend is accurate *if and only if* the hypervisor doesn't mess with the guest.

The different time backends can be enabled by passing either `TIME_BACKEND=fake` or `TIME_BACKEND=real` to `make`. By default, the `fake` time backend is enabled for optimal security.

Note that regardless of the selected time backend, the mushroom kernel may skip forward in time when it determines that no tasks can be executed until the clock advances to a certain timestamp. This is transparent to the workload.
