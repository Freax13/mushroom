use core::{
    cmp,
    ffi::c_void,
    sync::atomic::{AtomicU32, Ordering},
};

use alloc::{
    boxed::Box,
    collections::btree_map::{BTreeMap, Entry},
    format,
    string::ToString,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use arrayvec::ArrayVec;
use async_trait::async_trait;
use kernel_macros::register;

use crate::{
    error::{Result, bail, ensure, err},
    fs::{
        FileSystem,
        fd::{
            Events, FdFlags, FileLock, FileLockRecord, LazyFileLockRecord, NonEmptyEvents,
            OpenFileDescription, PipeBlocked, ReadBuf, StrongFileDescriptor, WriteBuf,
            common_ioctl, dir::open_dir, inotify::Watchers, stream_buffer,
            unix_socket::StreamUnixSocket,
        },
        node::{
            DirEntry, DirEntryName, DynINode, FileAccessContext, INode, Link, LinkLocation,
            directory::{Directory, dir_impls},
            new_ino,
        },
        path::{FileName, Path},
    },
    memory::page::KernelPage,
    rt::notify::Notify,
    spin::mutex::Mutex,
    user::process::{
        limits::CurrentNoFileLimit,
        syscall::{
            args::{
                ExtractableThreadState, FileMode, FileType, FileTypeAndMode, InputMode, LocalMode,
                OpenFlags, OutputMode, Pointer, Stat, Termios, Timespec,
            },
            traits::Abi,
        },
        thread::{Gid, ThreadGuard, Uid},
    },
};

use super::CharDev;

static PTYS: Mutex<BTreeMap<u32, Weak<PtyData>>> = Mutex::new(BTreeMap::new());

static PTY_COUNTER: AtomicU32 = AtomicU32::new(0);

const MAJOR: u16 = 5;

pub struct Ptmx;

#[register]
impl CharDev for Ptmx {
    const MAJOR: u16 = MAJOR;
    const MINOR: u8 = 2;

    fn new(
        _: LinkLocation,
        flags: OpenFlags,
        _stat: Stat,
        _fs: Arc<dyn FileSystem>,
        ctx: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        let mut guard = PTYS.lock();
        let data = (u32::MIN..=u32::MAX)
            .find_map(|_| {
                let index = PTY_COUNTER.fetch_add(1, Ordering::Relaxed);
                let Entry::Vacant(entry) = guard.entry(index) else {
                    return None;
                };
                let data = Arc::new(PtyData {
                    index,
                    ino: new_ino(),
                    uid: ctx.filesystem_user_id,
                    gid: ctx.filesystem_group_id,
                    internal: Mutex::new(PtyDataInternal {
                        locked: true,
                        master_closed: false,
                        num_slaves: 0,
                        termios: Termios::default(),
                        input_buffer: ArrayVec::new(),
                        output_buffer: ArrayVec::new(),
                        column_pointer: 0,
                    }),
                    notify: Notify::new(),
                    watchers: Arc::new(Watchers::new()),
                });
                entry.insert(Arc::downgrade(&data));
                Some(data)
            })
            .expect("TODO: figure out which error to return");

        Ok(StrongFileDescriptor::from(Pty {
            flags,
            master: true,
            data,
            file_lock: FileLock::anonymous(),
        }))
    }
}

struct Pty {
    flags: OpenFlags,
    master: bool,
    data: Arc<PtyData>,
    file_lock: FileLock,
}

pub struct PtyData {
    index: u32,
    ino: u64,
    uid: Uid,
    gid: Gid,
    internal: Mutex<PtyDataInternal>,
    notify: Notify,
    watchers: Arc<Watchers>,
}

struct PtyDataInternal {
    locked: bool,
    master_closed: bool,
    num_slaves: usize,

    termios: Termios,
    input_buffer: ArrayVec<u8, 4095>,
    output_buffer: ArrayVec<u8, 4096>,
    column_pointer: usize,
}

impl Pty {
    pub fn new_slave(data: Arc<PtyData>, flags: OpenFlags) -> Result<Self> {
        // Increment the reference count for the slave.
        let mut guard = data.internal.lock();
        ensure!(!guard.locked, Io);
        guard.num_slaves += 1;
        drop(guard);
        Ok(Self {
            flags,
            master: false,
            data,
            file_lock: FileLock::anonymous(),
        })
    }
}

#[async_trait]
impl OpenFileDescription for Pty {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn path(&self) -> Result<Path> {
        let path = format!("/dev/pts/{}", self.data.index);
        let path = Path::new(path.into_bytes()).unwrap();
        Ok(path)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: 0,
            ino: self.data.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(
                FileType::Char,
                FileMode::OWNER_WRITE | FileMode::OWNER_READ | FileMode::GROUP_WRITE,
            ),
            uid: self.data.uid,
            gid: self.data.gid,
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        todo!()
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        let mut ready_events = Events::empty();
        let guard = self.data.internal.lock();
        if self.master {
            ready_events.set(
                Events::READ,
                !guard.output_buffer.is_empty() || guard.num_slaves == 0,
            );
            ready_events.set(
                Events::WRITE,
                guard.input_buffer.len() < guard.input_buffer.capacity()
                    || guard
                        .input_buffer
                        .iter()
                        .copied()
                        .all(|c| !guard.is_line_end(c)),
            );
        } else {
            ready_events.set(
                Events::READ,
                guard
                    .input_buffer
                    .iter()
                    .copied()
                    .any(|c| guard.is_line_end(c))
                    || guard.master_closed,
            );
            ready_events.set(
                Events::WRITE,
                guard.output_buffer.len() < guard.output_buffer.capacity() - 1
                    || guard.master_closed,
            );
        }
        NonEmptyEvents::new(ready_events & events)
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        self.data
            .notify
            .wait_until(|| self.poll_ready(events))
            .await
    }

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        let buffer_len = buf.buffer_len();
        if buffer_len == 0 {
            return Ok(0);
        }

        let mut guard = self.data.internal.lock();
        if self.master {
            if guard.output_buffer.is_empty() {
                if guard.num_slaves == 0 {
                    bail!(Io);
                } else {
                    bail!(Again);
                }
            }

            let len = cmp::min(buffer_len, guard.output_buffer.len());
            buf.write(0, &guard.output_buffer[..len])?;
            drop(guard.output_buffer.drain(..len));
            drop(guard);

            self.data.notify.notify();

            Ok(len)
        } else {
            // Read input data for the slave.
            if guard.termios.local_modes.contains(LocalMode::ICANON) {
                let Some((line_end_idx, line_end_char)) = guard
                    .input_buffer
                    .iter()
                    .copied()
                    .enumerate()
                    .find(|&(_, c)| guard.is_line_end(c))
                else {
                    if guard.master_closed {
                        return Ok(0);
                    } else {
                        bail!(Again);
                    }
                };
                let read_len = if line_end_char != guard.termios.special_characters.eof {
                    line_end_idx + 1
                } else {
                    line_end_idx
                };
                let len = cmp::min(buffer_len, read_len);
                buf.write(0, &guard.input_buffer[..len])?;

                let remove_len = if len == read_len {
                    line_end_idx + 1
                } else {
                    len
                };
                drop(guard.input_buffer.drain(..remove_len));
                drop(guard);

                self.data.notify.notify();

                Ok(len)
            } else {
                let len = cmp::min(buffer_len, guard.input_buffer.len());
                buf.write(0, &guard.input_buffer[..len])?;
                drop(guard.input_buffer.drain(..len));
                drop(guard);

                self.data.notify.notify();

                Ok(len)
            }
        }
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        let buffer_len = buf.buffer_len();
        if buffer_len == 0 {
            return Ok(0);
        }

        let mut guard = self.data.internal.lock();

        let mut chunk = [0; 128];
        for i in (0..buffer_len).step_by(chunk.len()) {
            let chunk_len = cmp::min(chunk.len(), buffer_len - i);
            let chunk = &mut chunk[..chunk_len];
            buf.read(i, chunk)?;

            for (i, c) in (i..).zip(chunk.iter().copied()) {
                let res = if self.master {
                    guard.write_byte_to_input(c)
                } else {
                    guard.write_byte_to_output(c)
                };
                match res {
                    Ok(()) => self.data.notify.notify(),
                    Err(err) => {
                        // If no bytes have been written yet, return the error,
                        // otherwise return how many bytes have been written.
                        if i == 0 {
                            return Err(err);
                        } else {
                            return Ok(i);
                        }
                    }
                }
            }
        }

        Ok(buffer_len)
    }

    fn splice_from(
        &self,
        _read_half: &stream_buffer::ReadHalf,
        _offset: Option<usize>,
        _len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        todo!();
    }

    fn splice_to(
        &self,
        _write_half: &stream_buffer::WriteHalf,
        _offset: Option<usize>,
        _len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        todo!();
    }

    fn get_page(&self, _page_idx: usize, _shared: bool) -> Result<KernelPage> {
        bail!(NoDev)
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }

    fn ioctl(
        &self,
        thread: &mut ThreadGuard,
        cmd: u32,
        arg: Pointer<c_void>,
        abi: Abi,
    ) -> Result<u64> {
        match cmd {
            0x80045430 => {
                // TIOCGPTN
                ensure!(self.master, Inval);
                thread.virtual_memory().write(arg.cast(), self.data.index)?;
                Ok(0)
            }
            0x40045431 => {
                // TIOCSPTLCK
                let lock = thread.virtual_memory().read(arg.cast::<u32>())?;
                self.data.internal.lock().locked = lock != 0;
                Ok(0)
            }
            0x5401 => {
                // TCGETS
                let termios = self.data.internal.lock().termios;
                thread
                    .virtual_memory()
                    .write_with_abi(arg.cast(), termios, abi)?;
                Ok(0)
            }
            0x5403 => {
                // TCSADRAIN
                // TODO: Implement this correctly.
                let termios = thread
                    .virtual_memory()
                    .read_with_abi(arg.cast::<Termios>(), abi)?;
                self.data.internal.lock().termios = termios;
                Ok(0)
            }
            0x5441 => {
                // TIOCGPTPEER
                let flags = arg.get().as_u64();

                let pty = Self::new_slave(self.data.clone(), OpenFlags::from_bits_retain(flags))?;
                let no_file_limit = CurrentNoFileLimit::extract_from_thread(thread);
                let fd = thread.thread.fdtable.lock().insert(
                    pty,
                    FdFlags::from_bits_retain(flags),
                    no_file_limit,
                )?;
                Ok(fd.get() as u64)
            }
            _ => common_ioctl(self, thread, cmd, arg, abi),
        }
    }

    fn as_tty(&self) -> Option<Arc<PtyData>> {
        Some(self.data.clone())
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        let mut guard = self.data.internal.lock();
        if self.master {
            guard.master_closed = true;
        } else {
            guard.num_slaves -= 1;
        }
        drop(guard);

        self.data.notify.notify();
    }
}

impl PtyDataInternal {
    fn write_byte_to_input(&mut self, mut c: u8) -> Result<()> {
        // "If ISTRIP is set, valid input bytes shall first be stripped to
        // seven bits; otherwise, all eight bits shall be processed."
        if self.termios.input_modes.contains(InputMode::STRIP) {
            c &= 0b0111_1111;
        }

        // "If ECHO is set, input characters shall be echoed back to the
        // terminal."
        if self.termios.local_modes.contains(LocalMode::ECHO) {
            let _ = self.write_byte_to_output(c);
        } else if c == b'\n' && self.termios.local_modes.contains(LocalMode::ECHONL) {
            // "If ECHONL and ICANON are set, the <newline> character shall be
            // echoed even if ECHO is not set."
            let _ = self.write_byte_to_output(c);
        }

        // "If INLCR is set, a received NL character shall be translated into a
        // CR character."
        if self.termios.input_modes.contains(InputMode::NLCR) && c == b'\n' {
            return self.queue_input_char(b'\r');
        }

        // "If IGNCR is set, a received CR character shall be ignored (not
        // read)."
        if self.termios.input_modes.contains(InputMode::GNCR) && c == b'\r' {
            return Ok(());
        }

        // "If IGNCR is not set and ICRNL is set, a received CR character shall
        // be translated into an NL character."
        if !self.termios.input_modes.contains(InputMode::GNCR)
            && self.termios.input_modes.contains(InputMode::CRNL)
            && c == b'\r'
        {
            return self.queue_input_char(b'\n');
        }

        self.queue_input_char(c)
    }

    fn queue_input_char(&mut self, c: u8) -> Result<()> {
        if !self.termios.local_modes.contains(LocalMode::ICANON) {
            if self.input_buffer.len() < self.input_buffer.capacity() - 2 {
                self.input_buffer.push(c);
            }
            return Ok(());
        }

        assert_ne!(c, 0);

        if self.is_line_end(c) {
            self.input_buffer.try_push(c).map_err(|_| err!(Again))?;
            return Ok(());
        } else if c == self.termios.special_characters.erase {
            todo!()
        } else if c == self.termios.special_characters.intr {
            todo!()
        } else if c == self.termios.special_characters.kill {
            todo!()
        } else if c == self.termios.special_characters.lnext {
            todo!()
        } else if c == self.termios.special_characters.quit {
            todo!()
        } else if c == self.termios.special_characters.reprint {
            todo!()
        } else if c == self.termios.special_characters.start {
            todo!()
        } else if c == self.termios.special_characters.stop {
            todo!()
        } else if c == self.termios.special_characters.susp {
            todo!()
        } else if c == self.termios.special_characters.werase {
            todo!()
        } else if self.input_buffer.len() < self.input_buffer.capacity() - 2 {
            self.input_buffer.push(c);
        }

        Ok(())
    }

    fn is_line_end(&self, c: u8) -> bool {
        c == b'\n'
            || c == self.termios.special_characters.eol
            || c == self.termios.special_characters.eol2
            || c == self.termios.special_characters.eof
    }

    fn write_byte_to_output(&mut self, c: u8) -> Result<()> {
        if !self.termios.output_modes.contains(OutputMode::POST) {
            return self.queue_output_char(c, false);
        }

        // "If ONLCR is set, the NL character shall be transmitted as the CR-NL
        // character pair."
        if self.termios.output_modes.contains(OutputMode::NLCR) && c == b'\n' {
            self.queue_output_char(b'\r', false)?;
            self.queue_output_char(b'\n', true).unwrap();
            return Ok(());
        }

        // "If OCRNL is set, the CR character shall be transmitted as the NL character."
        if self.termios.output_modes.contains(OutputMode::CRNL) && c == b'\r' {
            return self.queue_output_char(b'\n', false);
        }

        // "If ONOCR is set, no CR character shall be transmitted when at
        // column 0 (first position)."
        if self.termios.output_modes.contains(OutputMode::NOCR)
            && c == b'\r'
            && self.column_pointer == 0
        {
            return Ok(());
        }

        self.queue_output_char(c, false)
    }

    fn queue_output_char(&mut self, c: u8, extra_capacity: bool) -> Result<()> {
        // Some characters need to be queue in pairs. We need to avoid the
        // situation, where only one the first byte in the pair can be queued.
        // The last index can only be used for the second byte in a pair.
        if !extra_capacity {
            ensure!(
                self.output_buffer.len() < self.output_buffer.capacity() - 1,
                Again
            );
        }
        self.output_buffer.try_push(c).map_err(|_| err!(Again))?;

        // "The column pointer shall also be set to 0 if the CR character is
        // actually transmitted."
        if c == b'\r' {
            self.column_pointer = 0;
        } else if c == b'\n' {
            // "If ONLRET is set, the NL character is assumed to do the
            // carriage-return function; the column pointer shall be set to 0
            // and the delays specified for CR shall be used."
            if self.termios.output_modes.contains(OutputMode::NLRET) {
                self.column_pointer = 0;
            } else {
                // "Otherwise, the NL character is assumed to do just the line-
                // feed function; the column pointer remains unchanged."
            }
        } else {
            self.column_pointer += 1;
        }

        Ok(())
    }
}

pub struct DevPtsDirectory {
    this: Weak<Self>,
    ino: u64,
    location: LinkLocation,
    file_lock_record: LazyFileLockRecord,
    watchers: Watchers,
}

impl DevPtsDirectory {
    pub fn new(location: LinkLocation) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            ino: new_ino(),
            location,
            file_lock_record: LazyFileLockRecord::new(),
            watchers: Watchers::new(),
        })
    }
}

impl INode for DevPtsDirectory {
    dir_impls!();

    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Dir, FileMode::from_bits_retain(0o777)),
            uid: Uid::SUPER_USER,
            gid: Gid::SUPER_USER,
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        todo!()
    }

    fn open(
        &self,
        _: LinkLocation,
        flags: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        open_dir(self.this.upgrade().unwrap(), flags)
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        bail!(Perm)
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        Ok(())
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {}

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        self.file_lock_record.get()
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

impl Directory for DevPtsDirectory {
    fn location(&self) -> &LinkLocation {
        &self.location
    }

    fn get_node(&self, file_name: &FileName, _ctx: &FileAccessContext) -> Result<Link> {
        let bytes = file_name.as_bytes();
        let str = core::str::from_utf8(bytes).map_err(|_| err!(NoEnt))?;
        let index = str.parse().map_err(|_| err!(NoEnt))?;
        let pty = PTYS.lock().get(&index).cloned().ok_or(err!(NoEnt))?;
        let strong = pty.upgrade().ok_or(err!(NoEnt))?;

        let node = Arc::new(PtsChar {
            pty,
            watchers: strong.watchers.clone(),
        });
        let location =
            LinkLocation::new(self.this.upgrade().unwrap(), file_name.clone().into_owned());
        Ok(Link { location, node })
    }

    fn create_file(
        &self,
        _: FileName<'static>,
        _: FileMode,
        _: Uid,
        _: Gid,
    ) -> Result<Result<Link, Link>> {
        bail!(NoEnt)
    }

    fn create_dir(&self, _: FileName<'static>, _: FileMode, _: Uid, _: Gid) -> Result<DynINode> {
        bail!(NoEnt)
    }

    fn create_link(
        &self,
        _file_name: FileName<'static>,
        _target: Path,
        _uid: Uid,
        _gid: Gid,
        _create_new: bool,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn create_char_dev(
        &self,
        _file_name: FileName<'static>,
        _major: u16,
        _minor: u8,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn create_fifo(
        &self,
        _file_name: FileName<'static>,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn bind_socket(
        &self,
        _file_name: FileName<'static>,
        _mode: FileMode,
        _uid: Uid,
        _gid: Gid,
        _: &StreamUnixSocket,
        _socketname: &Path,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn is_empty(&self) -> bool {
        false
    }

    fn list_entries(&self, _ctx: &mut FileAccessContext) -> Result<Vec<DirEntry>> {
        let mut entries = vec![DirEntry {
            ino: self.ino,
            ty: FileType::Dir,
            name: DirEntryName::Dot,
        }];
        if let Some(entry) = self.location.parent()
            && let Ok(stat) = entry.stat()
        {
            entries.push(DirEntry {
                ino: stat.ino,
                ty: FileType::Dir,
                name: DirEntryName::DotDot,
            });
        }

        let guard = PTYS.lock();
        entries.extend(guard.values().filter_map(Weak::upgrade).map(|data| {
            let file_name = data.index.to_string();
            let file_name = FileName::new(file_name.as_bytes()).unwrap().into_owned();
            DirEntry {
                ino: data.ino,
                ty: FileType::Char,
                name: DirEntryName::FileName(file_name),
            }
        }));

        Ok(entries)
    }

    fn delete_non_dir(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(Perm)
    }

    fn delete_dir(&self, _file_name: FileName<'static>) -> Result<()> {
        bail!(Perm)
    }

    fn rename(
        &self,
        _oldname: FileName<'static>,
        _check_is_dir: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
        _no_replace: bool,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn exchange(
        &self,
        _oldname: FileName<'static>,
        _new_dir: DynINode,
        _newname: FileName<'static>,
    ) -> Result<()> {
        bail!(NoEnt)
    }

    fn hard_link(
        &self,
        _oldname: FileName<'static>,
        _follow_symlink: bool,
        _new_dir: DynINode,
        _newname: FileName<'static>,
    ) -> Result<Option<Path>> {
        bail!(NoEnt)
    }
}

struct PtsChar {
    pty: Weak<PtyData>,
    watchers: Arc<Watchers>,
}

impl INode for PtsChar {
    fn stat(&self) -> Result<Stat> {
        let pty = self.pty.upgrade().ok_or(err!(NoEnt))?;
        Ok(Stat {
            dev: 0,
            ino: pty.ino,
            nlink: 0,
            mode: FileTypeAndMode::new(
                FileType::Char,
                FileMode::OWNER_WRITE | FileMode::OWNER_READ | FileMode::GROUP_WRITE,
            ),
            uid: pty.uid,
            gid: pty.gid,
            rdev: 0,
            size: 0,
            blksize: 1024,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        todo!()
    }

    fn open(
        &self,
        _: LinkLocation,
        flags: OpenFlags,
        _: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        let pty = self.pty.upgrade().ok_or(err!(NoEnt))?;
        let pty = Pty::new_slave(pty, flags)?;
        Ok(StrongFileDescriptor::new(pty))
    }

    fn chmod(&self, _: FileMode, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn chown(&self, _: Uid, _: Gid, _: &FileAccessContext) -> Result<()> {
        todo!()
    }

    fn update_times(&self, _ctime: Timespec, _atime: Option<Timespec>, _mtime: Option<Timespec>) {
        todo!()
    }

    fn file_lock_record(&self) -> &Arc<FileLockRecord> {
        todo!()
    }

    fn watchers(&self) -> &Watchers {
        &self.watchers
    }
}

pub struct Tty;

#[register]
impl CharDev for Tty {
    const MAJOR: u16 = MAJOR;
    const MINOR: u8 = 0;

    fn new(
        _: LinkLocation,
        flags: OpenFlags,
        _stat: Stat,
        _fs: Arc<dyn FileSystem>,
        ctx: &FileAccessContext,
    ) -> Result<StrongFileDescriptor> {
        let process = ctx.process.as_ref().ok_or(err!(Srch))?;
        let data = process
            .process_group()
            .session()
            .controlling_terminal()
            .ok_or(err!(NxIo))?;
        Ok(StrongFileDescriptor::from(Pty::new_slave(data, flags)?))
    }
}
