use alloc::vec::Vec;
use bytemuck::{Pod, Zeroable, bytes_of, pod_read_unaligned};

use crate::{
    net::netlink::{MsgHeader, MsgHeaderFlags, NLMSG_DONE},
    rt::{mpmc, mpsc},
};

pub async fn handle(pid: u32, tx: mpmc::Sender<Vec<u8>>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Ok(rx) = rx.recv().await {
        // TODO: Don't panic when bounds checks fail.

        let mut rx = &*rx;
        while !rx.is_empty() {
            let Some(header) = rx.get(..size_of::<MsgHeader>()) else {
                log::warn!("truncated header");
                break;
            };
            let header = pod_read_unaligned::<MsgHeader>(header);

            if (header.len as usize) < size_of::<MsgHeader>() {
                log::warn!("message is too short");
                break;
            }
            let Some(message) = rx.get(..header.len as usize) else {
                log::warn!("truncated message");
                break;
            };
            rx = &rx[header.len as usize..];
            let payload = &message[size_of::<MsgHeader>()..];

            if !header.flags.contains(MsgHeaderFlags::REQUEST) {
                continue;
            }

            log::debug!("{header:?} {payload:02x?}");

            const RTM_GETLINK: u16 = 0x12;
            const RTM_GETADDR: u16 = 0x16;
            match header.r#type {
                RTM_GETLINK | RTM_GETADDR => {
                    let response_header = MsgHeader {
                        len: size_of::<MsgHeader>() as u32,
                        r#type: NLMSG_DONE,
                        flags: MsgHeaderFlags::MULTI,
                        seq: header.seq,
                        pid,
                    };
                    let _ = tx.send(bytes_of(&response_header).to_vec());
                }
                ty => log::warn!("unknown request type: {ty:#02x}"),
            }
        }
    }

    log::debug!("Netlink socket task ended");
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
#[expect(dead_code)]
struct IfInfoMsg {
    pub family: u8,
    _padding: u8,
    /// Device type
    pub r#type: u16,
    /// Interface index
    pub index: i32,
    /// Device flags
    pub flags: u32,
    /// change mask
    pub change: u32,
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
#[expect(dead_code)]
struct RtAttr {
    pub len: u16,
    pub r#type: u16,
}
