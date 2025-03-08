use core::cmp;

use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::{
        btree_map::{BTreeMap, Entry},
        vec_deque::VecDeque,
    },
    format,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use async_trait::async_trait;
use usize_conversions::{FromUsize, usize_from};
use x86_64::{align_down, align_up};

use super::super::{Events, FileLock, OpenFileDescription};
use crate::{
    error::{Result, bail, ensure, err},
    fs::{
        FileSystem,
        fd::{
            FdFlags, FileDescriptorTable, NonEmptyEvents, OpenFileDescriptionData, PipeBlocked,
            ReadBuf, StrongFileDescriptor, VectoredUserBuf, WriteBuf,
            stream_buffer::{self},
        },
        node::{FileAccessContext, bind_socket, get_socket, new_ino},
        ownership::Ownership,
        path::Path,
    },
    rt::notify::{Notify, NotifyOnDrop},
    spin::{
        mutex::{Mutex, MutexGuard},
        once::Once,
    },
    user::process::{
        limits::CurrentNoFileLimit,
        memory::VirtualMemory,
        syscall::{
            args::{
                Accept4Flags, CmsgHdr, FileMode, FileType, FileTypeAndMode, MsgHdr, OpenFlags,
                Pointer, RecvFromFlags, SentToFlags, ShutdownHow, SocketAddr, SocketType, Stat,
                Timespec, UnixAddr, pointee::SizedPointee,
            },
            traits::Abi,
        },
        thread::{Gid, Uid},
    },
};

const CAPACITY: usize = 262144;

static ABSTRACT_SOCKETS: Mutex<BTreeMap<Vec<u8>, Weak<OpenFileDescriptionData<StreamUnixSocket>>>> =
    Mutex::new(BTreeMap::new());

pub struct StreamUnixSocket {
    this: Weak<OpenFileDescriptionData<Self>>,
    ino: u64,
    internal: Mutex<StreamUnixSocketInternal>,
    socketname: Mutex<UnixAddr>,
    activate_notify: Notify,
    mode: Once<Mode>,
    file_lock: FileLock,
}

#[derive(Clone)]
struct StreamUnixSocketInternal {
    flags: OpenFlags,
    ownership: Ownership,
}

enum Mode {
    Active(Active),
    Passive(Passive),
}

impl StreamUnixSocket {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(flags: OpenFlags, uid: Uid, gid: Gid) -> StrongFileDescriptor {
        StrongFileDescriptor::new_cyclic(|this| Self {
            this: this.clone(),
            ino: new_ino(),
            internal: Mutex::new(StreamUnixSocketInternal {
                flags,
                ownership: Ownership::new(FileMode::OWNER_READ | FileMode::OWNER_WRITE, uid, gid),
            }),
            socketname: Mutex::new(UnixAddr::Unnamed),
            activate_notify: Notify::new(),
            mode: Once::new(),
            file_lock: FileLock::anonymous(),
        })
    }

    pub fn new_pair(
        flags: OpenFlags,
        uid: Uid,
        gid: Gid,
    ) -> (StrongFileDescriptor, StrongFileDescriptor) {
        let (read_half1, write_half2) = LockedBuffer::new();
        let (read_half2, write_half1) = LockedBuffer::new();
        (
            StrongFileDescriptor::new_cyclic(|this| Self {
                this: this.clone(),
                ino: new_ino(),
                internal: Mutex::new(StreamUnixSocketInternal {
                    flags,
                    ownership: Ownership::new(
                        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
                        uid,
                        gid,
                    ),
                }),
                socketname: Mutex::new(UnixAddr::Unnamed),
                activate_notify: Notify::new(),
                mode: Once::with_value(Mode::Active(Active {
                    write_half: write_half1,
                    read_half: read_half1,
                    peername: UnixAddr::Unnamed,
                })),
                file_lock: FileLock::anonymous(),
            }),
            StrongFileDescriptor::new_cyclic(|this| Self {
                this: this.clone(),
                ino: new_ino(),
                internal: Mutex::new(StreamUnixSocketInternal {
                    flags,
                    ownership: Ownership::new(
                        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
                        uid,
                        gid,
                    ),
                }),
                socketname: Mutex::new(UnixAddr::Unnamed),
                activate_notify: Notify::new(),
                mode: Once::with_value(Mode::Active(Active {
                    write_half: write_half2,
                    read_half: read_half2,
                    peername: UnixAddr::Unnamed,
                })),
                file_lock: FileLock::anonymous(),
            }),
        )
    }

    pub fn bind(&self, socketname: UnixAddr) -> Result<Weak<OpenFileDescriptionData<Self>>> {
        ensure!(!matches!(socketname, UnixAddr::Unnamed), Inval);

        let mut guard = self.socketname.lock();
        // Make sure that the socket is not already bound.
        ensure!(matches!(*guard, UnixAddr::Unnamed), Inval);
        *guard = socketname;
        drop(guard);

        Ok(self.this.clone())
    }
}

#[async_trait]
impl OpenFileDescription for StreamUnixSocket {
    fn flags(&self) -> OpenFlags {
        self.internal.lock().flags | OpenFlags::RDWR
    }

    fn path(&self) -> Result<Path> {
        Path::new(format!("socket:[{}]", self.ino).into_bytes())
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.internal.lock().flags = flags;
    }

    fn set_non_blocking(&self, non_blocking: bool) {
        self.internal
            .lock()
            .flags
            .set(OpenFlags::NONBLOCK, non_blocking);
    }

    fn read(&self, buf: &mut dyn ReadBuf) -> Result<usize> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active
            .read_half
            .lock()
            .read(buf)
            .map(|(len, _ancillary_data)| len)
    }

    fn recv_from(&self, buf: &mut dyn ReadBuf, _flags: RecvFromFlags) -> Result<usize> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active
            .read_half
            .lock()
            .read(buf)
            .map(|(len, _ancillary_data)| len)
    }

    fn recv_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        fdtable: &FileDescriptorTable,
        no_file_limit: CurrentNoFileLimit,
    ) -> Result<usize> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };

        let mut vectored_buf = VectoredUserBuf::new(vm, msg_hdr.iov, msg_hdr.iovlen, abi)?;
        let (len, ancillary_data) = active.read_half.lock().read(&mut vectored_buf)?;

        if let Some(ancillary_data) = ancillary_data {
            let align = match abi {
                Abi::I386 => 4,
                Abi::Amd64 => 8,
            };
            let mut control = msg_hdr.control;
            let mut control_len = align_down(msg_hdr.controllen, align);

            if let Some(fds) = ancillary_data.rights.filter(|fds| !fds.is_empty()) {
                let mut cmsg_header = CmsgHdr {
                    len: 0,
                    level: 1,
                    r#type: 1,
                };
                let header_len = cmsg_header.size(abi);
                cmsg_header.len = u64::from_usize(header_len);
                if let Some(mut payload_len) = control_len.checked_sub(u64::from_usize(header_len))
                {
                    for fd in fds {
                        let Some(next_payload_len) = payload_len.checked_sub(4) else {
                            break;
                        };
                        payload_len = next_payload_len;

                        let flags = FdFlags::empty(); // TODO: Set CLOEXEC if requested
                        let Ok(num) = fdtable.insert(fd, flags, no_file_limit) else {
                            break;
                        };

                        vm.write(
                            control.bytes_offset(usize_from(cmsg_header.len)).cast(),
                            num,
                        )?;

                        cmsg_header.len += 4;
                    }

                    vm.write_with_abi(control, cmsg_header, abi)?;

                    let offset = align_up(cmsg_header.len, align);
                    control = control.bytes_offset(usize_from(offset));
                    control_len -= offset;
                }
            }

            _ = control;

            msg_hdr.controllen -= control_len;
        } else {
            msg_hdr.controllen = 0;
        }

        Ok(len)
    }

    fn write(&self, buf: &dyn WriteBuf) -> Result<usize> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        active.write_half.lock().write(buf, None)
    }

    fn send_to(
        &self,
        _vm: &VirtualMemory,
        buf: &dyn WriteBuf,
        _: SentToFlags,
        addr: Pointer<SocketAddr>,
        _addrlen: usize,
    ) -> Result<usize> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        ensure!(addr.is_null(), IsConn);
        active.write_half.lock().write(buf, None)
    }

    fn send_msg(
        &self,
        vm: &VirtualMemory,
        abi: Abi,
        msg_hdr: &mut MsgHdr,
        fdtable: &FileDescriptorTable,
    ) -> Result<usize> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };

        let ancillary_data = if msg_hdr.controllen > 0 {
            let mut ancillary_data = AncillaryData::default();

            while msg_hdr.controllen > 0 {
                let (len, header) = vm.read_sized_with_abi(msg_hdr.control, abi)?;
                ensure!(msg_hdr.controllen >= header.len, Inval);
                let buffer_len = usize_from(header.len).checked_sub(len).ok_or(err!(Inval))?;

                match (header.level, header.r#type) {
                    (1, 1) => {
                        // SCM_RIGHTS
                        ensure!(buffer_len % 4 == 0, Inval);
                        let num_fds = buffer_len / 4;

                        ensure!(ancillary_data.rights.is_none(), Inval);

                        let fds = (0..num_fds)
                            .map(|i| {
                                let fd =
                                    vm.read(msg_hdr.control.bytes_offset(len).cast().add(i))?;
                                fdtable.get_strong(fd)
                            })
                            .collect::<Result<_>>()?;
                        ancillary_data.rights = Some(fds);
                    }
                    _ => bail!(Inval),
                }

                let align = match abi {
                    Abi::I386 => 4,
                    Abi::Amd64 => 8,
                };
                let offset = align_up(header.len, align);
                msg_hdr.control = msg_hdr.control.bytes_offset(usize_from(offset));
                msg_hdr.controllen -= offset;
            }

            Some(ancillary_data)
        } else {
            None
        };

        let vectored_buf = VectoredUserBuf::new(vm, msg_hdr.iov, msg_hdr.iovlen, abi)?;
        active
            .write_half
            .lock()
            .write(&vectored_buf, ancillary_data)
    }

    fn splice_from(
        &self,
        read_half: &stream_buffer::ReadHalf,
        offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        ensure!(offset.is_none(), Inval);
        active.read_half.lock().splice_from(read_half, len)
    }

    fn splice_to(
        &self,
        write_half: &stream_buffer::WriteHalf,
        offset: Option<usize>,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        ensure!(offset.is_none(), Inval);
        active.read_half.lock().splice_to(write_half, len)
    }

    fn shutdown(&self, how: ShutdownHow) -> Result<()> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        match how {
            ShutdownHow::Rd => active.read_half.lock().shutdown(),
            ShutdownHow::Wr => active.write_half.lock().shutdown(),
            ShutdownHow::RdWr => {
                active.read_half.lock().shutdown();
                active.write_half.lock().shutdown();
            }
        }
        Ok(())
    }

    fn bind(
        &self,
        virtual_memory: &VirtualMemory,
        addr: Pointer<SocketAddr>,
        addrlen: usize,
        ctx: &mut FileAccessContext,
    ) -> Result<()> {
        let mut raw = vec![0; addrlen];
        virtual_memory.read_bytes(addr.get(), &mut raw)?;
        let addr = UnixAddr::parse(&raw)?;

        match addr {
            UnixAddr::Pathname(path) => {
                let guard = self.internal.lock();
                bind_socket(
                    &path,
                    guard.ownership.mode(),
                    guard.ownership.uid(),
                    guard.ownership.gid(),
                    self,
                    ctx,
                )
            }
            UnixAddr::Unnamed => {
                // Auto-bind. Pick a 5-hexdigit abstract name and bind it.

                const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";
                let mut candidates = HEX_DIGITS.iter().flat_map(|&a| {
                    HEX_DIGITS.iter().flat_map(move |&b| {
                        HEX_DIGITS.iter().flat_map(move |&c| {
                            HEX_DIGITS.iter().flat_map(move |&d| {
                                HEX_DIGITS.iter().map(move |&e| [a, b, c, d, e])
                            })
                        })
                    })
                });

                let mut guard = ABSTRACT_SOCKETS.lock();
                let name = candidates
                    .find(|name| !guard.contains_key(name.as_slice()))
                    .ok_or(err!(AddrInUse))?;
                let entry = guard.entry(name.to_vec());
                let Entry::Vacant(entry) = entry else {
                    bail!(AddrInUse);
                };
                let addr = UnixAddr::Abstract(name.to_vec());
                let weak = self.bind(addr)?;
                entry.insert(weak);
                Ok(())
            }
            UnixAddr::Abstract(ref name) => {
                let mut guard = ABSTRACT_SOCKETS.lock();
                let entry = guard.entry(name.to_owned());
                let Entry::Vacant(entry) = entry else {
                    bail!(AddrInUse);
                };
                let weak = self.bind(addr)?;
                entry.insert(weak);
                Ok(())
            }
        }
    }

    fn get_socket_option(&self, _: Abi, level: i32, optname: i32) -> Result<Vec<u8>> {
        match (level, optname) {
            (1, 3) => {
                // SO_TYPE
                let ty = SocketType::Stream as u32;
                Ok(ty.to_le_bytes().to_vec())
            }
            (1, 4) => Ok(0u32.to_ne_bytes().to_vec()), // SO_ERROR
            _ => bail!(Inval),
        }
    }

    fn set_socket_option(
        &self,
        _: Arc<VirtualMemory>,
        _: Abi,
        level: i32,
        optname: i32,
        _optval: Pointer<[u8]>,
        _optlen: i32,
    ) -> Result<()> {
        match (level, optname) {
            (1, 2) => Ok(()), // SO_REUSEADDR
            _ => bail!(Inval),
        }
    }

    fn get_socket_name(&self) -> Result<Vec<u8>> {
        Ok(self.socketname.lock().to_bytes())
    }

    fn get_peer_name(&self) -> Result<Vec<u8>> {
        let mode = self.mode.get().ok_or(err!(NotConn))?;
        let Mode::Active(active) = mode else {
            bail!(NotConn);
        };
        Ok(active.peername.to_bytes())
    }

    fn listen(&self, backlog: usize) -> Result<()> {
        let mut initialized = false;
        let mode = self.mode.call_once(|| {
            initialized = true;
            Mode::Passive(Passive {
                connect_notify: Notify::new(),
                internal: Mutex::new(PassiveInternal {
                    queue: VecDeque::new(),
                    backlog: 0,
                }),
            })
        });
        if initialized {
            self.activate_notify.notify();
        }
        let Mode::Passive(passive) = mode else {
            bail!(IsConn)
        };

        let mut guard = passive.internal.lock();
        let was_full = guard.backlog >= guard.queue.len();
        guard.backlog = cmp::max(backlog, 1);
        let is_full = guard.backlog >= guard.queue.len();
        drop(guard);

        // If the backlog size was changed, notify sockets that are trying to connect.
        if was_full && !is_full {
            passive.connect_notify.notify();
        }

        Ok(())
    }

    fn accept(&self, flags: Accept4Flags) -> Result<(StrongFileDescriptor, Vec<u8>)> {
        let mode = self.mode.get().ok_or(err!(Inval))?;
        let Mode::Passive(passive) = mode else {
            bail!(Inval)
        };
        let mut guard = passive.internal.lock();
        let active = guard.queue.pop_front().ok_or(err!(Again))?;
        drop(guard);

        let addr = active.peername.to_bytes();

        let mut internal = self.internal.lock().clone();
        internal
            .flags
            .set(OpenFlags::NONBLOCK, flags.contains(Accept4Flags::NONBLOCK));
        internal
            .flags
            .set(OpenFlags::CLOEXEC, flags.contains(Accept4Flags::CLOEXEC));
        let socket = StrongFileDescriptor::new_cyclic(|this| StreamUnixSocket {
            this: this.clone(),
            ino: new_ino(),
            internal: Mutex::new(internal),
            socketname: self.socketname.clone(),
            activate_notify: Notify::new(),
            mode: Once::with_value(Mode::Active(active)),
            file_lock: FileLock::anonymous(),
        });
        Ok((socket, addr))
    }

    async fn connect(
        &self,
        virtual_memory: &VirtualMemory,
        addr: Pointer<SocketAddr>,
        addrlen: usize,
        ctx: &mut FileAccessContext,
    ) -> Result<()> {
        let mut raw = vec![0; addrlen];
        virtual_memory.read_bytes(addr.get(), &mut raw)?;
        let addr = UnixAddr::parse(&raw)?;

        let server = match addr {
            UnixAddr::Pathname(path) => get_socket(&path, ctx)?,
            UnixAddr::Unnamed => bail!(Inval),
            UnixAddr::Abstract(name) => ABSTRACT_SOCKETS
                .lock()
                .get(&name)
                .and_then(Weak::upgrade)
                .ok_or(err!(ConnRefused))?,
        };
        let server_mode = server.mode.get().ok_or(err!(ConnRefused))?;
        let Mode::Passive(passive) = server_mode else {
            bail!(ConnRefused)
        };

        passive
            .connect_notify
            .wait_until(|| {
                let mut guard = passive.internal.lock();
                if guard.backlog <= guard.queue.len() {
                    return None;
                }

                let res = self
                    .mode
                    .init(|| {
                        let (read_half1, write_half2) = LockedBuffer::new();
                        let (read_half2, write_half1) = LockedBuffer::new();

                        guard.queue.push_back(Active {
                            write_half: write_half2,
                            read_half: read_half2,
                            peername: self.socketname.lock().clone(),
                        });
                        passive.connect_notify.notify();

                        self.activate_notify.notify();

                        Mode::Active(Active {
                            write_half: write_half1,
                            read_half: read_half1,
                            peername: server.socketname.lock().clone(),
                        })
                    })
                    .map(drop)
                    .map_err(|_| err!(IsConn));
                Some(res)
            })
            .await?;
        Ok(())
    }

    fn poll_ready(&self, events: Events) -> Option<NonEmptyEvents> {
        let mode = self.mode.get()?;
        match mode {
            Mode::Active(active) => NonEmptyEvents::zip(
                active.read_half.lock().poll_read(events),
                active.write_half.lock().poll_write(events),
            ),
            Mode::Passive(passive) => {
                let guard = passive.internal.lock();
                let mut ready_events = Events::empty();
                ready_events.set(Events::READ, !guard.queue.is_empty());
                NonEmptyEvents::new(ready_events & events)
            }
        }
    }

    fn epoll_ready(&self, events: Events) -> Result<Option<NonEmptyEvents>> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> NonEmptyEvents {
        let mode = self.activate_notify.wait_until(|| self.mode.get()).await;
        match mode {
            Mode::Active(active) => {
                let write_ready = active
                    .write_half
                    .notify
                    .wait_until(|| active.write_half.lock().poll_write(events));
                let read_ready = active
                    .read_half
                    .notify
                    .wait_until(|| active.read_half.lock().poll_read(events));
                NonEmptyEvents::select(write_ready, read_ready).await
            }
            Mode::Passive(passive) => {
                passive
                    .connect_notify
                    .wait_until(|| {
                        let guard = passive.internal.lock();
                        let mut ready_events = Events::empty();
                        ready_events.set(Events::READ, !guard.queue.is_empty());
                        ready_events &= events;
                        NonEmptyEvents::new(ready_events)
                    })
                    .await
            }
        }
    }

    async fn ready_for_write(&self, count: usize) {
        let Some(mode) = self.mode.get() else {
            return;
        };
        let Mode::Active(active) = mode else {
            return;
        };
        active
            .write_half
            .notify
            .wait_until(|| active.write_half.lock().can_write(count).then_some(()))
            .await;
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        self.internal.lock().ownership.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Socket, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
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
        bail!(BadF)
    }

    fn file_lock(&self) -> Result<&FileLock> {
        Ok(&self.file_lock)
    }
}

struct Active {
    write_half: LockedBuffer,
    read_half: LockedBuffer,
    peername: UnixAddr,
}

struct Buffer {
    data: VecDeque<u8>,
    capacity: usize,
    boundaries: VecDeque<MessageBoundary>,
    total_sent: usize,
    total_received: usize,
    shutdown: bool,
}

struct MessageBoundary {
    boundary: usize,
    data: AncillaryData,
    len: usize,
}

#[derive(Default)]
struct AncillaryData {
    rights: Option<Vec<StrongFileDescriptor>>,
}

impl Buffer {
    pub fn new() -> Self {
        Self {
            data: VecDeque::new(),
            capacity: CAPACITY,
            boundaries: VecDeque::new(),
            total_sent: 0,
            total_received: 0,
            shutdown: false,
        }
    }
}

struct LockedBuffer {
    buffer: Arc<Mutex<Buffer>>,
    notify: NotifyOnDrop,
}

impl LockedBuffer {
    pub fn new() -> (Self, Self) {
        let arc = Arc::new(Mutex::new(Buffer::new()));
        let notify = Arc::new(Notify::new());
        (
            Self {
                buffer: arc.clone(),
                notify: NotifyOnDrop(notify.clone()),
            },
            Self {
                buffer: arc,
                notify: NotifyOnDrop(notify),
            },
        )
    }

    pub fn lock(&self) -> BufferGuard {
        BufferGuard {
            buffer: self,
            guard: self.buffer.lock(),
        }
    }
}

struct BufferGuard<'a> {
    buffer: &'a LockedBuffer,
    guard: MutexGuard<'a, Buffer>,
}

impl BufferGuard<'_> {
    pub fn read(&mut self, buf: &mut dyn ReadBuf) -> Result<(usize, Option<AncillaryData>)> {
        let buffer = &mut *self.guard;

        let len = buf.buffer_len();
        if len == 0 {
            return Ok((0, None));
        }

        if buffer.data.is_empty() {
            if buffer.shutdown {
                return Ok((0, None));
            }

            if Arc::strong_count(&self.buffer.buffer) == 1 {
                return Ok((0, None));
            }

            bail!(Again)
        }

        let mut len = cmp::min(len, buffer.data.len());

        if let Some(front) = buffer.boundaries.front() {
            let next_message_boundary = (front.boundary + front.len) - buffer.total_received;
            len = cmp::min(len, next_message_boundary);
        }

        let (slice1, slice2) = buffer.data.as_slices();
        if let Some(slice) = slice1.get(..len) {
            buf.write(0, slice)?;
        } else {
            buf.write(0, slice1)?;
            buf.write(slice1.len(), &slice2[..len - slice1.len()])?;
        }
        buffer.data.drain(..len);

        buffer.total_received += len;

        let ancillary_data = buffer
            .boundaries
            .pop_front_if(|b| b.boundary < buffer.total_received)
            .map(|b| b.data);

        self.buffer.notify.notify();

        Ok((len, ancillary_data))
    }

    pub fn write(
        &mut self,
        buf: &dyn WriteBuf,
        ancillary_data: Option<AncillaryData>,
    ) -> Result<usize> {
        let buffer = &mut *self.guard;

        let len = buf.buffer_len();
        if len == 0 {
            // Yes, dropping `ancillary_data` is correct here.
            return Ok(0);
        }

        ensure!(!buffer.shutdown, Pipe);
        ensure!(Arc::strong_count(&self.buffer.buffer) > 1, Pipe);

        let len = buf.buffer_len();
        assert!(len <= buffer.capacity); // TODO
        ensure!(len < buffer.capacity, Again);

        buffer.data.resize(buffer.data.len() + len, 0);
        let (slice1, slice2) = buffer.data.as_mut_slices();
        if let Some(offset) = slice2.len().checked_sub(len) {
            buf.read(0, &mut slice2[offset..])?;
        } else {
            let offset = slice1.len() - (len - slice2.len());
            buf.read(0, &mut slice1[offset..])?;
            buf.read(len - slice2.len(), slice2)?;
        }

        if let Some(ancillary_data) = ancillary_data {
            buffer.boundaries.push_back(MessageBoundary {
                boundary: buffer.total_sent,
                data: ancillary_data,
                len,
            });
        }

        buffer.total_sent += len;

        self.buffer.notify.notify();

        Ok(len)
    }

    pub fn can_write(&self, count: usize) -> bool {
        let buffer = &*self.guard;
        buffer.capacity.saturating_sub(buffer.data.len()) >= count
            || buffer.shutdown
            || Arc::strong_count(&self.buffer.buffer) == 1
    }

    pub fn splice_from(
        &mut self,
        read_half: &stream_buffer::ReadHalf,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        let buffer = &mut *self.guard;

        if len == 0 {
            return Ok(Ok(0));
        }

        ensure!(!buffer.shutdown, Pipe);
        ensure!(Arc::strong_count(&self.buffer.buffer) > 1, Pipe);

        let len = cmp::min(len, buffer.capacity.saturating_sub(buffer.data.len()));
        read_half.splice_to(len, |buf, len| {
            buffer.data.extend(buf.drain(..len));
            buffer.total_sent += len;
            self.buffer.notify.notify();
        })
    }

    pub fn splice_to(
        &mut self,
        write_half: &stream_buffer::WriteHalf,
        len: usize,
    ) -> Result<Result<usize, PipeBlocked>> {
        let buffer = &mut *self.guard;

        if len == 0 {
            return Ok(Ok(0));
        }

        if buffer.data.is_empty() {
            if buffer.shutdown {
                return Ok(Ok(0));
            }

            if Arc::strong_count(&self.buffer.buffer) == 1 {
                return Ok(Ok(0));
            }

            bail!(Again)
        }

        let mut len = cmp::min(len, buffer.data.len());

        if let Some(front) = buffer.boundaries.front() {
            let next_message_boundary = (front.boundary + front.len) - buffer.total_received;
            len = cmp::min(len, next_message_boundary);
        }

        write_half.splice_from(len, |buf, len| {
            buf.extend(buffer.data.drain(..len));
            buffer.total_received += len;
            buffer
                .boundaries
                .pop_front_if(|b| b.boundary <= buffer.total_received);
            self.buffer.notify.notify();
        })
    }

    pub fn shutdown(&mut self) {
        self.guard.shutdown = true;
        self.buffer.notify.notify();
    }

    pub fn poll_read(&self, events: Events) -> Option<NonEmptyEvents> {
        let buffer = &*self.guard;

        let mut ready_events = Events::empty();
        let strong_count = Arc::strong_count(&self.buffer.buffer);
        ready_events.set(
            Events::READ,
            !buffer.data.is_empty() || strong_count == 1 || buffer.shutdown,
        );
        ready_events.set(Events::RDHUP, strong_count == 1 || buffer.shutdown);

        ready_events &= events;
        NonEmptyEvents::new(ready_events)
    }

    pub fn poll_write(&self, events: Events) -> Option<NonEmptyEvents> {
        let buffer = &*self.guard;

        let mut ready_events = Events::empty();
        let closed = buffer.shutdown || Arc::strong_count(&self.buffer.buffer) == 1;
        ready_events.set(Events::WRITE, buffer.data.len() < buffer.capacity || closed);
        ready_events &= events;
        ready_events.set(Events::HUP, closed);
        ready_events.set(Events::ERR, closed);

        NonEmptyEvents::new(ready_events)
    }
}

struct Passive {
    connect_notify: Notify,
    internal: Mutex<PassiveInternal>,
}

struct PassiveInternal {
    queue: VecDeque<Active>,
    backlog: usize,
}
