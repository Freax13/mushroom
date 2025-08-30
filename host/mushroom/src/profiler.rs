use std::{
    collections::HashMap,
    fs::{File, create_dir_all},
    io::{BufRead, BufReader, BufWriter, Write},
    mem::size_of,
    path::Path,
    process::{Command, Stdio},
    ptr::addr_of,
    sync::{Arc, Condvar, Mutex},
};

use anyhow::{Context, Error, Result, ensure};
use bitflags::bitflags;
use bytemuck::{NoUninit, bytes_of, cast_slice, zeroed_box};
use constants::{ApIndex, MAX_APS_COUNT};
use profiler_types::{AllEntries, CALL_STACK_CAPACITY, Entry, PerCpuEntries, ProfilerControl};
use rand::random;
use tracing::warn;

use crate::slot::{AnonymousPrivateMapping, Slot};

pub fn start_profile_collection(
    folder: ProfileFolder,
    memory_slots: &HashMap<u16, Slot>,
) -> Result<()> {
    let profiler_control = memory_slots
        .values()
        .find(|s| s.gpa().start_address().as_u64() == 0x800_0000_0000)
        .context("couldn't find profiler control region")?;
    let profiler_buffers = memory_slots
        .values()
        .find(|s| s.gpa().start_address().as_u64() == 0x800_4000_0000)
        .context("dculdn't find profiler buffers region")?;

    let profiler_control = profiler_control
        .shared_mapping()
        .cloned()
        .expect("profiler slot must have shared mapping");
    let profiler_buffers = profiler_buffers
        .shared_mapping()
        .cloned()
        .expect("profiler slot must have shared mapping");

    ensure!(
        profiler_control.len().get() >= size_of::<ProfilerControl>(),
        "profiler control region is too small"
    );
    ensure!(
        profiler_buffers.len().get() >= size_of::<AllEntries>(),
        "profiler buffers region is too small"
    );

    // Wrap the dat files in a `Mutex` and `Arc`. This allows us to share them
    // with other threads (and allows them to take temporarily ownership of a file).
    let dat_files = folder
        .dat_files
        .into_iter()
        .map(Mutex::new)
        .collect::<Arc<_>>();

    let processor_threads = (0..16)
        .map(|_| {
            let ctc = Arc::new(CollectorThreadControl::new());
            std::thread::spawn({
                let profiler_control = profiler_control.clone();
                let profiler_buffers = profiler_buffers.clone();
                let ctc = ctc.clone();
                let dat_files = dat_files.clone();
                move || collector_thread(profiler_control, profiler_buffers, ctc, dat_files)
            });
            ctc
        })
        .collect::<Vec<_>>();

    std::thread::spawn(move || notification_poll_thread(profiler_control, processor_threads));

    Ok(())
}

/// This function polls the `notify_flags` bits and dispatches the processing
/// of entries to other threads running `collector_thread`.
fn notification_poll_thread(
    profiler_control: Arc<AnonymousPrivateMapping>,
    collector_thread_controls: Vec<Arc<CollectorThreadControl>>,
) {
    let profiler_control = profiler_control
        .as_ptr()
        .as_ptr()
        .cast_const()
        .cast::<ProfilerControl>();

    let notify_flags_ptr = unsafe { &(*profiler_control).notify_flags };

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        /// The vCPU hasn't flushed out any entries yet.
        Idle,
        /// The vCPU flushed out any entries and we haven't started processing
        /// them yet.
        Notified,
        /// The vCPU flushed out any entries and
        /// `collector_thread_controls[idx]` is currently processing them.
        Processing(u8),
    }
    let mut states = [State::Idle; MAX_APS_COUNT as usize];

    let mut available_collector_thread_controls =
        (0..collector_thread_controls.len()).collect::<Vec<_>>();

    loop {
        // Check if there are any new vCPUs that flushed out entries.
        for (i, state) in states.iter_mut().enumerate() {
            if *state != State::Idle {
                continue;
            }

            if notify_flags_ptr.get(ApIndex::new(i as u8)) {
                *state = State::Notified;
            }
        }

        // Check if we finished processing entries.
        for (i, state) in states.iter_mut().enumerate() {
            let State::Processing(idx) = *state else {
                continue;
            };
            let idx = usize::from(idx);

            let Ok(res) = collector_thread_controls[idx].notify.try_lock() else {
                // If the lock can't be taken, the collector thread is probably
                // holding it because it's still processing entries.
                continue;
            };

            if res.is_some() {
                // If the index hasn't been taken out, the collector thread
                // hasn't started processing the entries yet.
                continue;
            }

            // The thread is done processing.
            *state = State::Idle;

            // Unset the notify bit.
            notify_flags_ptr.take(ApIndex::new(i as u8));

            // Re-add the idx to the list of available collector threads.
            available_collector_thread_controls.push(idx);
        }

        // Check if we can start processing any entries.
        while !available_collector_thread_controls.is_empty() {
            let Some((i, state)) = states
                .iter_mut()
                .enumerate()
                .find(|(_, state)| **state == State::Notified)
            else {
                break;
            };

            let idx = available_collector_thread_controls.pop().unwrap();

            // Tell the collector thread to start processing.
            let ctc = &collector_thread_controls[idx];
            *ctc.notify.lock().unwrap() = Some(u8::try_from(i).unwrap());
            ctc.condvar.notify_one();

            // Update the state.
            *state = State::Processing(u8::try_from(idx).unwrap());
        }
    }
}

struct CollectorThreadControl {
    condvar: Condvar,
    notify: Mutex<Option<u8>>,
}

impl CollectorThreadControl {
    pub fn new() -> Self {
        Self {
            condvar: Condvar::new(),
            notify: Mutex::new(None),
        }
    }
}

/// This function waits until it receives an index from `notification_poll_thread`,
/// reads the entries for the vCPU with that index and writes them to disk.
fn collector_thread(
    profiler_control: Arc<AnonymousPrivateMapping>,
    profiler_buffers: Arc<AnonymousPrivateMapping>,
    control: Arc<CollectorThreadControl>,
    dat_files: Arc<[Mutex<File>]>,
) {
    let mut buffer = zeroed_box::<PerCpuEntries>();

    let mut guard = control.notify.lock().unwrap();

    let profiler_control = profiler_control
        .as_ptr()
        .as_ptr()
        .cast_const()
        .cast::<ProfilerControl>();
    let profiler_buffers = profiler_buffers
        .as_ptr()
        .as_ptr()
        .cast_const()
        .cast::<AllEntries>();

    loop {
        guard = control.condvar.wait_while(guard, |a| a.is_none()).unwrap();

        // Get a reference to the entries.
        let idx = guard.take().unwrap();
        let idx = usize::from(idx);
        let header = unsafe {
            // SAFETY: The kernel won't touch this before we unset the notify
            // flag, so there can't be a data race.
            (*profiler_control).headers[idx]
        };

        let bytes = if !header.lost {
            let entries = unsafe {
                // SAFETY: The kernel won't touch this before we unset the notify
                // flag, so there can't be a data race.
                let ptr = addr_of!((*profiler_buffers)[idx].entries);
                let ptr = ptr.cast::<Entry>().add(header.start_idx);
                core::slice::from_raw_parts(ptr, header.len)
            };

            // Calculate the timestamp scale.
            let tsc_mhz = unsafe {
                // SAFETY: The kernel only sets this once before any data is
                // flushed out, so there can't be a data race.
                (*profiler_control).tsc_mhz
            };
            const MHZ_INV: u64 = 1_000_000;
            const GHZ_INV: u64 = 1_000_000_000;
            let frequency = tsc_mhz * MHZ_INV;
            // TODO: Support frequencies that don't evenly divide a second if AMD
            //       ever launches a CPU where this isn't the case.
            assert_eq!(GHZ_INV % frequency, 0);
            let scale = GHZ_INV / frequency;

            // Scale the timestamp and copy the event.
            let buffer = &mut buffer.entries[..header.len];
            for (dest, src) in buffer.iter_mut().zip(entries) {
                dest.time = src.time * scale;
                dest.event = src.event;
            }

            cast_slice::<_, u8>(buffer)
        } else {
            warn!("lost profiler data");

            const LOST_ENTRY: Entry = Entry {
                time: 0,
                event: 0x2a, // type=Lost (2), more=0, magic=0b101
            };
            bytes_of(&LOST_ENTRY)
        };

        // Take the file lock before signaling that we're done to prevent
        // out-of-order writes.
        let mut file_guard = dat_files[idx].lock().unwrap();

        // Signal that we're done reading.
        *guard = None;

        // Write the data to disk.
        file_guard.write_all(bytes).unwrap();
    }
}

pub struct ProfileFolder {
    dat_files: Vec<File>,
}

impl ProfileFolder {
    pub fn new(folder: impl AsRef<Path>, kernel: impl AsRef<Path>) -> Result<Self> {
        let folder = folder.as_ref();
        let kernel = kernel.as_ref();
        let session_id = random();
        create_dir_all(folder).context("failed to create folder")?;
        create_info_file(folder).context("failed to create info file")?;
        create_sym_file(folder, kernel).context("failed to create sym file")?;
        create_task_file(folder, session_id).context("failed to create task file")?;
        create_map_file(folder, session_id).context("failed to create map file")?;
        let dat_files = create_dat_files(folder).context("failed to create dat files")?;
        Ok(Self { dat_files })
    }
}

fn create_info_file(folder: &Path) -> Result<(), anyhow::Error> {
    let info_file = File::create(folder.join("info"))?;
    let mut info_file = BufWriter::new(info_file);

    let header = UftraceHeader {
        magic: UftraceHeader::MAGIC,
        version: UftraceHeader::VERSION,
        header_size: u16::try_from(size_of::<UftraceHeader>()).unwrap(),
        byte_order: ByteOrder::LittleEndian,
        adddress_size: AddressSize::SixtyFourBits,
        feat_mask: FeatMask::TASK_SESSION,
        info_mask: InfoMask::TASKINFO,
        max_stack: u16::try_from(CALL_STACK_CAPACITY).unwrap(),
        unused: [0; 6],
    };
    info_file.write_all(bytes_of(&header))?;

    writeln!(info_file, "taskinfo:lines=2")?;
    writeln!(info_file, "taskinfo:nr_tid={MAX_APS_COUNT}")?;
    write!(info_file, "taskinfo:tids=")?;
    for i in 0..MAX_APS_COUNT {
        if i != 0 {
            write!(info_file, ",")?;
        }
        write!(info_file, "{i}")?;
    }
    writeln!(info_file)?;

    info_file.flush()?;
    Ok(())
}

fn create_sym_file(folder: &Path, kernel: &Path) -> Result<()> {
    let sym_file = File::create(folder.join("kernel.sym"))?;
    let mut sym_file = BufWriter::new(sym_file);

    // Launch nm.
    let mut nm = Command::new("nm")
        .arg("-S")
        .arg(kernel)
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to run nm")?;

    // Modify the output of nm and write it to a file.
    let stdout = nm.stdout.as_mut().unwrap();
    let mut stdout = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        let len = stdout.read_line(&mut line)?;
        if len == 0 {
            break;
        }
        let line = line.trim_end_matches('\n');

        // Clear the upper bits for higher half addresses. The trace data is
        // also truncated in the same way.
        if let Some(line) = line.strip_prefix("ffff8") {
            writeln!(sym_file, "00000{line}")?;
        } else {
            writeln!(sym_file, "{line}")?;
        }
    }

    let status = nm.wait()?;
    ensure!(status.success(), "nm failed");

    sym_file.flush()?;
    Ok(())
}

fn create_task_file(folder: &Path, session_id: u64) -> Result<()> {
    let task_file = File::create(folder.join("task.txt"))?;
    let mut task_file = BufWriter::new(task_file);

    let pid = 1;
    writeln!(
        task_file,
        "SESS timestamp=0.0 pid={pid} sid={session_id:016x} exename=\"kernel\""
    )?;
    for i in 0..MAX_APS_COUNT {
        writeln!(task_file, "TASK timestamp=0.0 tid={i} pid={pid}")?;
    }

    task_file.flush()?;
    Ok(())
}

fn create_map_file(folder: &Path, session_id: u64) -> Result<()> {
    let map_file = File::create(folder.join(format!("sid-{session_id:016x}.map")))?;
    let mut map_file = BufWriter::new(map_file);

    writeln!(
        map_file,
        "0000000000000000-0000700000000000 r-xp 00000000 00:00 0                           kernel"
    )?;
    writeln!(
        map_file,
        "00007f0000000000-00007fffffffffff rw-p 00000000 00:00 0                           [stack]"
    )?;

    map_file.flush()?;
    Ok(())
}

fn create_dat_files(folder: &Path) -> Result<Vec<File>> {
    (0..MAX_APS_COUNT)
        .map(|i| File::create(folder.join(format!("{i}.dat"))).map_err(Error::from))
        .collect()
}

#[derive(Clone, Copy, NoUninit)]
#[repr(C)]
struct UftraceHeader {
    magic: [u8; 8],
    version: u32,
    header_size: u16,
    byte_order: ByteOrder,
    adddress_size: AddressSize,
    feat_mask: FeatMask,
    info_mask: InfoMask,
    max_stack: u16,
    unused: [u8; 6],
}

impl UftraceHeader {
    const MAGIC: [u8; 8] = *b"Ftrace!\0";
    const VERSION: u32 = 4;
}

#[derive(Clone, Copy, NoUninit)]
#[repr(u8)]
enum ByteOrder {
    LittleEndian = 1,
}

#[derive(Clone, Copy, NoUninit)]
#[repr(u8)]
enum AddressSize {
    SixtyFourBits = 2,
}

bitflags! {
    #[derive(Clone, Copy, NoUninit)]
    #[repr(transparent)]
    struct FeatMask: u64 {
        const TASK_SESSION = 1 << 1;
    }
}

bitflags! {
    #[derive(Clone, Copy, NoUninit)]
    #[repr(transparent)]
    struct InfoMask: u64 {
        const TASKINFO = 1 << 7;
    }
}
