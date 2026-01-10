use core::{
    arch::asm,
    mem::{offset_of, size_of},
    sync::atomic::{AtomicU64, Ordering},
};

use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
use bit_field::BitField;
use bytemuck::{
    NoUninit, Zeroable, bytes_of, bytes_of_mut, cast, cast_slice_mut,
    checked::{self, pod_read_unaligned},
    from_bytes_mut,
};
use constants::MAX_APS_COUNT;
use log::debug;
use snp_types::{
    attestation::{
        AttestionReport, KeySelect, MsgReportReq, MsgReportRspHeader, MsgReportRspStatus,
    },
    ghcb::{
        Ghcb, PageOperation, PageStateChangeEntry, PageStateChangeHeader, ProtocolVersion,
        SHARED_BUFFER_SIZE,
        msr_protocol::{self, GhcbInfo, GhcbProtocolMsr, TerminateReasonCode},
    },
    guest_message::{Algo, Content, ContentV1, Message},
    intercept::{VMEXIT_IOIO, VMEXIT_MSR},
    secrets::Secrets,
    vmsa::{SevFeatures, VmsaTweakBitmap},
};
use volatile::{VolatilePtr, map_field};
use x86_64::structures::paging::{PageSize, PhysFrame, Size2MiB, Size4KiB, frame::PhysFrameRange};

use crate::{per_cpu::PerCpu, shared};

fn secrets() -> &'static Secrets {
    unsafe extern "C" {
        #[link_name = "secrets"]
        static SECRETS: Secrets;
    }
    unsafe { &SECRETS }
}

pub fn vmsa_tweak_bitmap() -> &'static VmsaTweakBitmap {
    let Secrets::V3(v3) = secrets();
    &v3.vmsa_tweak_bitmap
}

/// Initialize a GHCB and pass it to the closure.
pub fn with_ghcb<R, F>(f: F) -> Result<R, GhcbInUse>
where
    F: for<'a> FnOnce(VolatilePtr<'a, Ghcb>, PhysFrame) -> R,
{
    let per_cpu = PerCpu::get();

    if per_cpu.ghcb_in_use.replace(true) {
        return Err(GhcbInUse(()));
    }

    shared! {
        static GHCB_STORAGE: [Ghcb; MAX_APS_COUNT as usize] = [Ghcb::ZERO; MAX_APS_COUNT as usize];
    }

    let frame = GHCB_STORAGE.frame() + u64::from(per_cpu.vcpu_index.as_u8());

    if !per_cpu.ghcb_registered.get() {
        register_ghcb(frame);
        per_cpu.ghcb_registered.set(true);
    }

    let mut msr = GhcbProtocolMsr::MSR;
    unsafe {
        msr.write(u64::from(GhcbInfo::GhcbGuestPhysicalAddress {
            address: frame,
        }));
    }

    let ghcb = GHCB_STORAGE
        .as_ptr()
        .as_slice()
        .index(usize::from(per_cpu.vcpu_index.as_u8()));

    let res = f(ghcb, frame);

    per_cpu.ghcb_in_use.set(false);

    Ok(res)
}

#[derive(Debug)]
pub struct GhcbInUse(());

fn register_ghcb(request_address: PhysFrame) {
    let mut msr = GhcbProtocolMsr::MSR;

    // Write the request.
    let request = u64::from(GhcbInfo::RegisterGhcbGpaRequest {
        address: request_address,
    });
    unsafe { msr.write(request) }

    // Execute the request.
    vmgexit();

    // Read the response.
    let response = GhcbInfo::try_from(unsafe { msr.read() }).unwrap();

    // Verify the response.
    let GhcbInfo::RegisterGhcbGpaResponse {
        address: response_address,
    } = response
    else {
        panic!("unexpected response: {response:?}")
    };
    assert_eq!(Some(request_address), response_address);
}

fn vmgexit() {
    // LLVM doesn't support the `vmgexit` instruction
    unsafe { asm!("rep vmmcall", options(nomem, nostack, preserves_flags)) }
}

fn interruptable_vmgexit() {
    unsafe {
        asm!(
            "66:",
            "test byte ptr fs:[{INTERRUPTED_OFFSET}], 1",
            "jnz 67f",
            // LLVM doesn't support the `vmgexit` instruction
            "rep vmmcall",
            "67:",
            ".pushsection .interruptable",
            ".quad 66b",
            ".quad 67b",
            ".popsection",
            INTERRUPTED_OFFSET = const offset_of!(PerCpu, interrupted),
            options(readonly, nostack, preserves_flags),
        );
    }
}

/// A macro to write to a field of the GHCB and also mark it in the valid
/// bitmap.
macro_rules! ghcb_write {
    ($ghcb:ident.$field:ident = $value:expr) => {{
        let value = $value;
        let bit_offset_start = offset_of!(Ghcb, $field);
        let bit_offset_end = bit_offset_start + size_of_val(&value);
        map_field!($ghcb.$field).write(value);
        map_field!($ghcb.valid_bitmap).update(|mut value| {
            for i in bit_offset_start / 8..bit_offset_end / 8 {
                value.set_bit(i, true);
            }
            value
        });
    }};
}

pub fn ioio_write(port: u16, value: u32) {
    with_ghcb(|ghcb, _frame| {
        ghcb.write(Ghcb::ZERO);
        map_field!(ghcb.protocol_version).write(ProtocolVersion::VERSION2);

        let mut sw_exit_info1 = 0;
        sw_exit_info1.set_bit(0, false); // OUT instruction
        sw_exit_info1.set_bit(6, true); // 32-bit operand size
        sw_exit_info1.set_bits(16..=31, u64::from(port));

        ghcb_write!(ghcb.sw_exit_code = VMEXIT_IOIO);
        ghcb_write!(ghcb.sw_exit_info1 = sw_exit_info1);
        ghcb_write!(ghcb.sw_exit_info2 = 0);
        ghcb_write!(ghcb.rax = u64::from(value));

        vmgexit();
    })
    .unwrap();
}

pub fn page_state_change(address: PhysFrame, operation: msr_protocol::PageOperation) {
    let mut msr = GhcbProtocolMsr::MSR;

    // Save the GHCB MSR.
    let prev_value = unsafe { msr.read() };

    // Write the request.
    let request = u64::from(GhcbInfo::SnpPageStateChangeRequest { operation, address });
    unsafe { msr.write(request) }

    // Execute the request.
    vmgexit();

    // Read the response.
    let response = GhcbInfo::try_from(unsafe { msr.read() }).unwrap();

    // Restore the GHCB MSR.
    unsafe {
        msr.write(prev_value);
    }

    // Verify the response.
    let GhcbInfo::SnpPageStateChangeResponse { error_code } = response else {
        panic!("unexpected response: {response:?}")
    };
    assert_eq!(error_code, None);
}

pub fn page_state_change_multiple(mut range: PhysFrameRange, operation: PageOperation) {
    with_ghcb(|ghcb, frame| {
        let shared_buffer_addr =
            frame.start_address().as_u64() + offset_of!(Ghcb, shared_buffer) as u64;

        while range.start < range.end {
            ghcb.write(Ghcb::ZERO);
            map_field!(ghcb.protocol_version).write(ProtocolVersion::VERSION2);
            ghcb_write!(ghcb.sw_exit_code = 0x8000_0010);
            ghcb_write!(ghcb.sw_exit_info1 = 0);
            ghcb_write!(ghcb.sw_exit_info2 = 0);
            ghcb_write!(ghcb.sw_scratch = shared_buffer_addr);

            let mut shared_buffer = [0; SHARED_BUFFER_SIZE];
            let (header, entries) = shared_buffer.split_at_mut(size_of::<PageStateChangeHeader>());
            let header = from_bytes_mut::<PageStateChangeHeader>(header);
            let entries = cast_slice_mut::<_, PageStateChangeEntry>(entries);

            for (i, entry) in (0..).zip(entries.iter_mut()) {
                if range.start >= range.end {
                    break;
                }
                if let Some(frame) =
                    PhysFrame::<Size2MiB>::from_start_address(range.start.start_address())
                        .ok()
                        .filter(|&frame| (frame + 1).start_address() <= range.end.start_address())
                {
                    *entry = PageStateChangeEntry::new(operation, frame);
                    range.start += frame.size() / Size4KiB::SIZE;
                } else {
                    let frame = range.start;
                    *entry = PageStateChangeEntry::new(operation, frame);
                    range.start += frame.size() / Size4KiB::SIZE;
                }
                header.end_entry = i;
            }

            map_field!(ghcb.shared_buffer).write(shared_buffer);

            vmgexit();

            let mut header = PageStateChangeHeader::zeroed();
            let bytes = bytes_of_mut(&mut header);
            map_field!(ghcb.shared_buffer)
                .as_slice()
                .index(..bytes.len())
                .copy_into_slice(bytes);
            debug_assert!(header.cur_entry > header.end_entry);

            let status = map_field!(ghcb.sw_exit_info2).read();
            debug_assert_eq!(status, 0);
        }
    })
    .unwrap();
}

pub fn write_msr(msr: u32, value: u64) -> Result<(), GhcbInUse> {
    with_ghcb(|ghcb, _frame| {
        ghcb.write(Ghcb::ZERO);
        map_field!(ghcb.protocol_version).write(ProtocolVersion::VERSION2);

        ghcb_write!(ghcb.sw_exit_code = VMEXIT_MSR);
        ghcb_write!(ghcb.sw_exit_info1 = 1);
        ghcb_write!(ghcb.sw_exit_info2 = 0);
        ghcb_write!(ghcb.rcx = u64::from(msr));
        ghcb_write!(ghcb.rax = value.get_bits(0..=31));
        ghcb_write!(ghcb.rdx = value.get_bits(32..=63));

        vmgexit();
    })
}

pub trait GuestRequest: NoUninit {
    const MSG_TYPE: u8;
    const MSG_VERSION: u8;
}

impl GuestRequest for MsgReportReq {
    const MSG_TYPE: u8 = 5;
    const MSG_VERSION: u8 = 1;
}

pub fn build_request_message<T>(request: T) -> (u64, Message)
where
    T: GuestRequest,
{
    static MSG_SEQNO: AtomicU64 = AtomicU64::new(1);
    let msg_seqno = MSG_SEQNO.fetch_add(2, Ordering::SeqCst);

    let mut iv = [0; 12];
    iv[0..8].copy_from_slice(&msg_seqno.to_ne_bytes());
    let nonce = Nonce::from(iv);

    let msg_size = u16::try_from(size_of::<T>()).unwrap();

    let mut message = Message::new(
        [0; 0x20],
        msg_seqno,
        Algo::Aes256Gcm,
        Content::V1(ContentV1::new(
            0x60,
            T::MSG_TYPE,
            T::MSG_VERSION,
            msg_size,
            0,
            [0; 4000],
        )),
    );

    let associated_data = &bytes_of(&message)[0x30..=0x5f];
    let associated_data: [u8; 48] = pod_read_unaligned(associated_data);

    let Content::V1(content) = &mut message.content;
    let payload = &mut content.payload[..size_of::<T>()];
    payload.copy_from_slice(bytes_of(&request));

    let Secrets::V3(secrets) = secrets();
    let cipher = Aes256Gcm::new_from_slice(&secrets.vmpck0).unwrap();
    let tag = cipher
        .encrypt_in_place_detached(&nonce, &associated_data, payload)
        .unwrap();

    let tag = <[u8; 16]>::from(tag);
    message.auth_tag[..16].copy_from_slice(&tag);

    (msg_seqno, message)
}

pub fn extract_response(msg_seqno: u64, message: &mut Message) -> (u8, u8, &[u8]) {
    assert_eq!(message.msg_seqno, msg_seqno);

    let mut iv = [0; 12];
    iv[0..8].copy_from_slice(&msg_seqno.to_ne_bytes());
    let nonce = Nonce::from(iv);

    let auth_tag = Tag::from_slice(&message.auth_tag[..16]);

    let associated_data = &bytes_of(message)[0x30..=0x5f];
    let associated_data: [u8; 48] = pod_read_unaligned(associated_data);

    let Algo::Aes256Gcm = message.algo;

    let Content::V1(content) = &mut message.content;
    assert_eq!(content.msg_vmpck, 0);
    assert_eq!({ content.hdr_size }, 0x60);

    let msg_size = usize::from(content.msg_size);
    let payload = &mut content.payload[..msg_size];

    let Secrets::V3(secrets) = secrets();
    let cipher = Aes256Gcm::new_from_slice(&secrets.vmpck0).unwrap();
    cipher
        .decrypt_in_place_detached(&nonce, &associated_data, payload, auth_tag)
        .unwrap();

    (content.msg_type, content.msg_version, payload)
}

pub fn do_guest_request(request: Message) -> Message {
    debug!("executing guest request");

    shared! {
        static REQ: [u8; 0x1000] = [0; 0x1000];
        static RSP: [u8; 0x1000] = [0; 0x1000];
    }

    REQ.as_write_only_ptr().write(cast(request));

    let req_pa = REQ.frame().start_address();
    let rsp_pa = RSP.frame().start_address();

    let sw_exit_info2 = with_ghcb(|ghcb, _frame| {
        ghcb.write(Ghcb::ZERO);
        map_field!(ghcb.protocol_version).write(ProtocolVersion::VERSION2);

        ghcb_write!(ghcb.sw_exit_code = 0x8000_0011);
        ghcb_write!(ghcb.sw_exit_info1 = req_pa.as_u64());
        ghcb_write!(ghcb.sw_exit_info2 = rsp_pa.as_u64());

        vmgexit();

        map_field!(ghcb.sw_exit_info2).read()
    })
    .unwrap();
    assert_eq!(sw_exit_info2, 0);

    checked::cast(RSP.as_read_only_ptr().read())
}

pub fn create_attestation_report(report_data: [u8; 64]) -> AttestionReport {
    debug!("creating attestation report");

    let (msg_seqno, request_message) =
        build_request_message(MsgReportReq::new(report_data, 0, KeySelect::PreferVlek));

    let mut response_message = do_guest_request(request_message);

    let (msg_ty, msg_version, data) = extract_response(msg_seqno + 1, &mut response_message);
    assert_eq!(msg_ty, 6);
    assert_eq!(msg_version, 1);

    let (header, body) = data.split_at(size_of::<MsgReportRspHeader>());
    let header: MsgReportRspHeader = pod_read_unaligned(header);
    assert_eq!(header.status, MsgReportRspStatus::Success);
    let report_size = usize::try_from(header.report_size).unwrap();
    assert_eq!(report_size, size_of::<AttestionReport>());

    pod_read_unaligned(body)
}

pub fn get_host_data() -> [u8; 32] {
    let report = create_attestation_report([0; 64]);
    report.host_data()
}

pub fn create_ap(vmsa: PhysFrame, features: SevFeatures) {
    with_ghcb(|ghcb, _frame| {
        ghcb.write(Ghcb::ZERO);
        map_field!(ghcb.protocol_version).write(ProtocolVersion::VERSION2);

        let mut sw_exit_info1 = 0;
        sw_exit_info1.set_bits(32..=63, u64::from(PerCpu::current_vcpu_index().as_u8()));
        sw_exit_info1.set_bits(16..=19, 1); // VMPL: 1

        ghcb_write!(ghcb.rax = features.bits());
        ghcb_write!(ghcb.sw_exit_code = 0x8000_0013);
        ghcb_write!(ghcb.sw_exit_info1 = sw_exit_info1);
        ghcb_write!(ghcb.sw_exit_info2 = vmsa.start_address().as_u64());

        vmgexit();
    })
    .unwrap();
}

pub fn exit() -> ! {
    let mut msr = GhcbProtocolMsr::MSR;

    loop {
        // Write the request.
        let request = u64::from(GhcbInfo::TerminationRequest {
            reason_code: TerminateReasonCode::GENERAL_TERMINATION_REQUEST,
        });
        unsafe {
            msr.write(request);
        }

        vmgexit();
    }
}

pub fn run_vmpl(vmpl: u8) {
    let mut msr = GhcbProtocolMsr::MSR;

    // Write the request.
    let request = u64::from(GhcbInfo::SnpRunVmplRequest { vmpl });
    unsafe {
        msr.write(request);
    }

    interruptable_vmgexit();
}

pub fn set_hv_doorbell_page(frame: PhysFrame) {
    with_ghcb(|ghcb, _frame| {
        ghcb.write(Ghcb::ZERO);
        map_field!(ghcb.protocol_version).write(ProtocolVersion::VERSION2);

        ghcb_write!(ghcb.sw_exit_code = 0x8000_0014);
        ghcb_write!(ghcb.sw_exit_info1 = 1);
        ghcb_write!(ghcb.sw_exit_info2 = frame.start_address().as_u64());

        vmgexit();
    })
    .unwrap();

    with_ghcb(|ghcb, _frame| {
        ghcb.write(Ghcb::ZERO);
        map_field!(ghcb.protocol_version).write(ProtocolVersion::VERSION2);

        ghcb_write!(ghcb.sw_exit_code = 0x8000_0014);
        ghcb_write!(ghcb.sw_exit_info1 = 2);
        ghcb_write!(ghcb.sw_exit_info2 = 0);

        vmgexit();
    })
    .unwrap();
}
