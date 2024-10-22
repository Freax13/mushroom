# Attestation

Attestation is used to prove that a certain set of supervisor, kernel, workload init binary, and workload input were used to produce a certain output.
If any binary or input is changed, the change will be visible in the attestation report.
Notably, this includes malicious workload inputs:
Even if a malicious input manages to exploit the workload, it is impossible for the exploit to generate an attestation report that doesn't include the malicious workload input.
Attestation reports are signed by the hardware root of trust.

## Hardware-measured input memory

The supervisor, the kernel, and the workload init binary are added directly to the initial guest memory during launch.
On AMD SEV-SNP, this memory is added using `SNP_LAUNCH_UPDATE`.
On Intel TDX, this memory is added using `MEM.PAGE.ADD` and `MR.EXTEND`.

The hardware derives a launch measurement from the initial guest memory.
This launch measurement never changes unless the supervisor, the kernel, or the init binary changes.
On AMD SEV-SNP, the launch measurement is stored in the `MEASUREMENT` field in the attestation report.
On Intel TDX, the launch measurement is stored in the `MRTD` field in the TD quote.
The launch measurement is independent of the workload input and output.

`mushroom verify` computes the launch measurement for a given supervisor, kernel, and workload init binary and verifies that it matches the value in the attestation report.

#### Details

The initial memory is assembled by [`loader`](../common/loader/) sub-crate.
We use special linker scripts for the supervisor and kernel that explicitly specify physical addresses for all segments.
The loader parses the ELF binaries and generates load commands for each segment at the specified physical addresses.
On AMD SEV-SNP, the loader uses the segment permissions in the kernel binary as the VMPL 1 permissions used in `SNP_LAUNCH_UPDATE`.
On Intel TDX, the loader cannot add permissions for the L2 VM, so this is done by the supervisor during boot.

## Supervisor-measured input memory

The workload input is measured and verified by the supervisor before the workload is started.

The workload input is initially stored in unmeasured shared memory.
As the supervisor reads and verifies the input, it converts it into private memory.
The supervisor never interprets the input in any way, it only passes it forward to the workload kernel.

The supervisor verifies that the input matches a hypervisor-supplied hash.
This hash is also part of the attestation report.
Because the hash is part of the attestation report, this hypervisor can't change the input hash without this being visible in the attestation report, so the hash isn't considered an untrusted input even though it's supplied by the hypervisor.
On AMD SEV-SNP, the input hash is stored in the `HOST_DATA` field in the attestation report.
On Intel TDX, the input hash is stored in the first 32 bytes of the `MRCONFIGID` field in the TD quote.

`mushroom verify` computes the hash for a given input and verifies that it matches the value in the attestation report.

#### Details

Mushroom allows the input to be split up into multiple chunks.
Chunks are placed one after another in memory.

Each input chunk is preceded by a header containing the chunk length, its hash, the hash type, and the hash of the next chunk header:
```rust
#[repr(C)]
pub struct Header {
    pub input_len: u64,
    pub hash_type: HashType,
    pub hash: [u8; MAX_HASH_SIZE],
    pub next_hash: [u8; 32],
}
```
The first header is verified by hashing it with SHA-256 and comparing the digest to the hash in the attestation report (`HOST_DATA` or `MRCONFIGID`).
The following header(s) are verified by hashing it with SHA-256 and comparing the digest to the `next_hash` in the previous header.
Note that `hash` contains the digest of the chunk content whereas `next_hash` contains the digest of the next chunk header (**not** the next chunk content).
Because each chunk header contains the digest of the next chunk header and is therefore dependent on its content, the hashes have to be calculated from back to front, but the supervisor can verify the hashes from front to back.

The last chunk is marked with `input_len` being equal to `0xffff_ffff_ffff_ffff`.

### Why isn't the workload input measured as part of the launch measurement?

1. Separation of concerns: mushroom is designed for use cases where the relying party will verify many attestation reports for the same workload with different inputs.
   Separating the workload from its input simplifies the computations needed to verify attestation reports.
2. Performance: Adding memory to the launch measurement is fairly slow on AMD SEV-SNP.
   A large input could cause significant performance problems.

## Output

The workload output is hashed using SHA-256 and its digest placed into the attestation report.
The output size is also placed into the attestation report.
On AMD SEV-SNP, the output digest and size are placed in the `REPORT_DATA` field in the attestation report.
On Intel TDX, the output digest and size are placed in the `REPORTDATA` field in the TD quote.

Note that on both AMD SEV-SNP and Intel TDX, the `REPORT_DATA` and `REPORTDATA` fields are the only fields that can be influenced by the workload at runtime.
The workload cannot influence any other fields including the `MEASUREMENT`, `MRTD`, `HOST_DATA`, and `MRCONFIGID` fields as all of these are protected by the hardware.
If a malicous party were to change the supervisor, kernel, workload init binary or workload input that in such a way that it gains code execution within workload, the hardware will prevent the attacker from creating attestation reports that don't reflect the changed binaries/input.

`mushroom verify` computes the hash for a given output and verifies that the digest and output size match the values in the attestation report.

## Attestation report formats

### AMD SEV-SNP

On AMD SEV-SNP, the attestation report returned by mushroom contains an attestation report created by the hardware concatenated with the VCEK certificate that proves that the attestation report was generated by real hardware.
`mushroom verify` checks that the public key in the VCEK matches the signature in the attestation report and checks that the VCEK was signed by one of the built-in ASKs [^1].

[^1]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf

### Intel TDX

On Intel TDX, the attestation report is just a normal TD quote version 4 [^2].

Note that the supervisor outputs a TD report, not a TD quote.
It's the responsibility of the mushroom VMM to talk to the quote generation service running on the host to turn the TD report into a full TD quote.
This doesn't need to be done inside the TD guest.

[^2]: https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf

## Policies & SVNs

Mushroom verifies the trustworthiness of the TEE hardware/firmware by checking the policies and SVNs in attestation reports.
The mushroom CLI uses reasonable defaults for policies.
The default SVN minimums match the latest available SVNs at the time the mushroom is compiled, but these may become outdated when new TEE firmwares are released.
Library users have to specify their own allowed policy flags and minimum SVNs.
