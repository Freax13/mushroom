use core::{
    cmp,
    ffi::c_void,
    sync::atomic::{AtomicU32, Ordering},
};

use alloc::{
    boxed::Box,
    collections::{
        btree_map::{BTreeMap, Entry},
        vec_deque::VecDeque,
    },
    format,
    string::ToString,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
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
                ExtractableThreadState, FileMode, FileType, FileTypeAndMode, OpenFlags, Pointer,
                Stat, Termios, Timespec,
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
                        slave_buffer: VecDeque::new(),
                        master_buffer: VecDeque::new(),
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

    /// The buffer containing bytes sent to the slave.
    slave_buffer: VecDeque<u8>,
    /// The buffer containing bytes sent to the master.
    master_buffer: VecDeque<u8>,
}

impl Pty {
    const PTY_CAPACITY: usize = 0x4000;

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
                !guard.master_buffer.is_empty() || guard.num_slaves == 0,
            );
            ready_events.set(
                Events::WRITE,
                guard.slave_buffer.len() < Self::PTY_CAPACITY
                    || !guard.slave_buffer.contains(&b'\n'),
            );
        } else {
            ready_events.set(
                Events::READ,
                guard.slave_buffer.contains(&b'\n') || guard.master_closed,
            );
            ready_events.set(
                Events::WRITE,
                guard.master_buffer.len() < Self::PTY_CAPACITY || guard.master_closed,
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
            if guard.master_buffer.is_empty() {
                if guard.num_slaves == 0 {
                    bail!(Io);
                } else {
                    bail!(Again);
                }
            }

            let count = cmp::min(guard.master_buffer.len(), buffer_len);
            let (half1, half2) = guard.master_buffer.as_slices();
            if let Some(buffer) = half1.get(..count) {
                buf.write(0, buffer)?;
            } else {
                buf.write(0, half1)?;
                buf.write(half1.len(), &half2[..count - half1.len()])?;
            }
            guard.master_buffer.drain(..count);
            drop(guard);

            self.data.notify.notify();

            Ok(count)
        } else {
            // Find the last newline character and add 1.
            let Some(available_count) = guard
                .slave_buffer
                .iter()
                .copied()
                .enumerate()
                .rev()
                .find(|(_, b)| *b == b'\n')
                .map(|(idx, _)| idx + 1)
            else {
                if guard.master_closed {
                    return Ok(0);
                } else {
                    bail!(Again);
                }
            };

            let count = cmp::min(available_count, buffer_len);
            let (half1, half2) = guard.slave_buffer.as_slices();
            if let Some(buffer) = half1.get(..count) {
                buf.write(0, buffer)?;
            } else {
                buf.write(0, half1)?;
                buf.write(half1.len(), &half2[..count - half1.len()])?;
            }
            guard.slave_buffer.drain(..count);
            drop(guard);

            self.data.notify.notify();

            Ok(count)
        }
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        let buffer_len = buf.buffer_len();
        if buffer_len == 0 {
            return Ok(0);
        }

        let mut guard = self.data.internal.lock();
        if self.master {
            // Up to `PTY_CAPACITY - 1` can always be written to normally.
            let len = cmp::min(
                buffer_len,
                (Self::PTY_CAPACITY - 1).saturating_sub(guard.slave_buffer.len()),
            );

            let start_idx = guard.slave_buffer.len();
            // Reserve some space for the new bytes.
            guard.slave_buffer.resize(start_idx + len, 0);

            let (first, second) = guard.slave_buffer.as_mut_slices();
            let res = if second.len() >= len {
                let second_len = second.len();
                buf.read(0, &mut second[second_len - len..])
            } else {
                let first_write_len = len - second.len();
                let first_len = first.len();
                buf.read(0, &mut first[first_len - first_write_len..])
                    .and_then(|_| buf.read(first_write_len, second))
            };

            // Rollback all bytes if an error occured.
            // FIXME: We should not roll back all bytes.
            if res.is_err() {
                guard.slave_buffer.truncate(start_idx);
            }

            let mut written = len;
            // The last byte in the buffer can only be a newline. If there's
            // still some bytes left to be processed and if there's still space
            // for a newline, try to find one.
            if buffer_len > len && guard.slave_buffer.len() < Self::PTY_CAPACITY {
                // The behavior depends on whether or not the buffer already contains a newline.
                if guard.slave_buffer.contains(&b'\n') {
                    // If the buffer contains a newline, fill the buffer up to the last byte and then block.
                    if buffer_len > written {
                        let mut byte = 0;
                        buf.read(written, core::array::from_mut(&mut byte))?;
                        guard.slave_buffer.push_back(byte);
                        written += 1;
                    }
                    ensure!(written > 0, Again);
                } else {
                    // If the buffer doesn't already contain a newline, try to
                    // find a newline and put it in the last byte.
                    let mut has_newline = false;
                    let mut buffer = [0; 512];
                    for i in (len..buffer_len).step_by(buffer.len()) {
                        let chunk_size = cmp::min(buffer.len(), buffer_len - i);
                        let buffer = &mut buffer[..chunk_size];
                        buf.read(i, buffer)?;
                        if buffer.contains(&b'\n') {
                            has_newline = true;
                            break;
                        }
                    }
                    if has_newline {
                        guard.slave_buffer.push_back(b'\n');
                    }

                    // Always report that all bytes have been written, even if some
                    // bytes didn't fit into the buffer.
                    written = buffer_len;
                }
            }
            drop(guard);

            self.data.notify.notify();

            Ok(written)
        } else {
            ensure!(!guard.master_closed, Io);

            let remaining_capacity = Self::PTY_CAPACITY - guard.master_buffer.len();
            ensure!(remaining_capacity > 0, Again);
            let len = cmp::min(buffer_len, remaining_capacity);

            let start_idx = guard.master_buffer.len();
            // Reserve some space for the new bytes.
            guard.master_buffer.resize(start_idx + len, 0);

            let (first, second) = guard.master_buffer.as_mut_slices();
            let res = if second.len() >= len {
                let second_len = second.len();
                buf.read(0, &mut second[second_len - len..])
            } else {
                let first_write_len = len - second.len();
                let first_len = first.len();
                buf.read(0, &mut first[first_len - first_write_len..])
                    .and_then(|_| buf.read(first_write_len, second))
            };

            // Rollback all bytes if an error occured.
            // FIXME: We should not roll back all bytes.
            if res.is_err() {
                guard.master_buffer.truncate(start_idx);
            }
            drop(guard);

            self.data.notify.notify();

            Ok(len)
        }
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
        if let Some(entry) = self.location.parent() {
            if let Ok(stat) = entry.stat() {
                entries.push(DirEntry {
                    ino: stat.ino,
                    ty: FileType::Dir,
                    name: DirEntryName::DotDot,
                });
            }
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
