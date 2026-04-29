use alloc::vec::Vec;

use crate::rt::{mpmc, mpsc};

pub async fn handle(_pid: u32, _tx: mpmc::Sender<Vec<u8>>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Ok(packet) = rx.recv().await {
        let _ = packet;
        todo!()
    }
}
