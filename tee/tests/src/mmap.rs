use std::{
    ffi::c_void,
    num::NonZeroUsize,
    os::fd::{AsFd, AsRawFd},
    ptr::NonNull,
};

use bytemuck::{Pod, bytes_of_mut};
use nix::{
    errno::Errno,
    fcntl::OFlag,
    libc::{self, off_t},
    sys::{
        memfd::{MFdFlags, memfd_create},
        mman::{MRemapFlags, MapFlags, ProtFlags, mmap, mmap_anonymous, mprotect, mremap, munmap},
    },
    unistd::{ftruncate, pipe2, read},
};

fn try_read<T>(ptr: NonNull<T>) -> Option<T>
where
    T: Pod,
{
    let (read_half, write_half) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).unwrap();

    let ptr = ptr.as_ptr().cast();
    let count = size_of::<T>();
    let res = unsafe { libc::write(write_half.as_raw_fd(), ptr, count) };
    if res as usize != count {
        return None;
    }

    let mut value = T::zeroed();
    let bytes = bytes_of_mut(&mut value);
    let n = read(&read_half, bytes).unwrap();
    assert_eq!(n, count);

    Some(value)
}

unsafe fn mmap_anonymous_with_guard_pages(
    addr: Option<NonZeroUsize>,
    length: NonZeroUsize,
    prot: ProtFlags,
    flags: MapFlags,
) -> nix::Result<NonNull<c_void>> {
    let padded_length = length.checked_add(0x2000).unwrap();
    let ptr = unsafe {
        mmap_anonymous(
            addr,
            padded_length,
            ProtFlags::PROT_READ,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | (flags & MapFlags::MAP_FIXED),
        )?
    };

    unsafe {
        mmap_anonymous(
            Some(ptr.addr().checked_add(0x1000).unwrap()),
            length,
            prot,
            flags | MapFlags::MAP_FIXED,
        )
    }
}

unsafe fn mmap_with_guard_pages<F>(
    addr: Option<NonZeroUsize>,
    length: NonZeroUsize,
    prot: ProtFlags,
    flags: MapFlags,
    f: F,
    offset: off_t,
) -> nix::Result<NonNull<c_void>>
where
    F: AsFd,
{
    let padded_length = length.checked_add(0x2000).unwrap();
    let ptr = unsafe {
        mmap_anonymous(
            addr,
            padded_length,
            ProtFlags::empty(),
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | (flags & MapFlags::MAP_FIXED),
        )?
    };

    unsafe {
        mmap(
            Some(ptr.addr().checked_add(0x1000).unwrap()),
            length,
            prot,
            flags | MapFlags::MAP_FIXED,
            f,
            offset,
        )
    }
}

#[test]
fn mremap_whole() {
    unsafe {
        let len = NonZeroUsize::new(0x3000).unwrap();
        let ptr = mmap_anonymous_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();

        let p0 = ptr.cast::<u64>();
        let p1 = ptr.byte_add(0x1000).cast::<u64>();
        let p2 = ptr.byte_add(0x2000).cast::<u64>();

        p0.write(!0);
        p1.write(!1);
        p2.write(!2);

        let new = mremap(p0.cast(), 0x3000, 0x4000, MRemapFlags::MREMAP_MAYMOVE, None).unwrap();
        let new_p0 = new.cast::<u64>();
        let new_p1 = new.byte_add(0x1000).cast::<u64>();
        let new_p2 = new.byte_add(0x2000).cast::<u64>();
        let new_p3 = new.byte_add(0x3000).cast::<u64>();

        // The mapping must have been moved.
        assert_ne!(new_p1, p1);

        assert_eq!(try_read(p0), None); // page unmapped
        assert_eq!(try_read(p1), None); // page unmapped
        assert_eq!(try_read(p2), None); // page unmapped

        assert_eq!(try_read(new_p0), Some(!0)); // untouched
        assert_eq!(try_read(new_p1), Some(!1)); // untouched
        assert_eq!(try_read(new_p2), Some(!2)); // untouched
        assert_eq!(try_read(new_p3), Some(0)); // zero-initialized
    }
}

#[test]
fn mremap_at_base() {
    unsafe {
        let len = NonZeroUsize::new(0x7000).unwrap();
        let ptr = mmap_anonymous_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();

        let p0 = ptr.cast::<u64>();
        let p1 = ptr.byte_add(0x1000).cast::<u64>();
        let p2 = ptr.byte_add(0x2000).cast::<u64>();

        p0.write(!0);
        p1.write(!1);
        p2.write(!2);

        let new = mremap(p0.cast(), 0x2000, 0x3000, MRemapFlags::MREMAP_MAYMOVE, None).unwrap();
        let new_p0 = new.cast::<u64>();
        let new_p1 = new.byte_add(0x1000).cast::<u64>();
        let new_p2 = new.byte_add(0x2000).cast::<u64>();

        // The mapping must have been moved.
        assert_ne!(new, ptr);

        assert_eq!(try_read(p0), None); // page unmapped
        assert_eq!(try_read(p1), None); // page unmapped
        assert_eq!(try_read(p2), Some(!2)); // untouched

        assert_eq!(try_read(new_p0), Some(!0)); // untouched
        assert_eq!(try_read(new_p1), Some(!1)); // untouched
        assert_eq!(try_read(new_p2), Some(0)); // zero-initialized
    }
}

#[test]
fn mremap_to_end() {
    unsafe {
        let len = NonZeroUsize::new(0x7000).unwrap();
        let ptr = mmap_anonymous_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();

        let p0 = ptr.cast::<u64>();
        let p1 = ptr.byte_add(0x1000).cast::<u64>();
        let p2 = ptr.byte_add(0x2000).cast::<u64>();

        p0.write(!0);
        p1.write(!1);
        p2.write(!2);

        let new = mremap(p1.cast(), 0x5000, 0x7000, MRemapFlags::MREMAP_MAYMOVE, None).unwrap();
        let new_p1 = new.cast::<u64>();
        let new_p2 = new.byte_add(0x1000).cast::<u64>();
        let new_p3 = new.byte_add(0x2000).cast::<u64>();

        // The mapping must have been moved.
        assert_ne!(new_p1, p1);

        assert_eq!(try_read(p0), Some(!0)); // untouched
        assert_eq!(try_read(p1), None); // page unmapped
        assert_eq!(try_read(p2), None); // page unmapped

        assert_eq!(try_read(new_p1), Some(!1)); // untouched
        assert_eq!(try_read(new_p2), Some(!2)); // untouched
        assert_eq!(try_read(new_p3), Some(0)); // zero-initialized
    }
}

#[test]
fn mremap_middle() {
    unsafe {
        let len = NonZeroUsize::new(0x7000).unwrap();
        let ptr = mmap_anonymous_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();

        let p0 = ptr.cast::<u64>();
        let p1 = ptr.byte_add(0x1000).cast::<u64>();
        let p2 = ptr.byte_add(0x2000).cast::<u64>();

        p0.write(!0);
        p1.write(!1);
        p2.write(!2);

        let new = mremap(p1.cast(), 0x1000, 0x2000, MRemapFlags::MREMAP_MAYMOVE, None).unwrap();
        let new_p1 = new.cast::<u64>();
        let new_p2 = new.byte_add(0x1000).cast::<u64>();

        // The mapping must have been moved.
        assert_ne!(new_p1, p1);

        assert_eq!(try_read(p0), Some(!0)); // untouched
        assert_eq!(try_read(p1), None); // page unmapped
        assert_eq!(try_read(p2), Some(!2)); // untouched

        assert_eq!(try_read(new_p1), Some(!1)); // untouched
        assert_eq!(try_read(new_p2), Some(0)); // zero-initialized
    }
}

#[test]
fn remap_grow_in_place() {
    unsafe {
        let len = NonZeroUsize::new(0x7000).unwrap();
        let ptr = mmap_anonymous_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();

        munmap(ptr.byte_add(0x4000), 0x3000).unwrap();

        let p0 = ptr.cast::<u64>();
        let p1 = ptr.byte_add(0x1000).cast::<u64>();
        let p2 = ptr.byte_add(0x2000).cast::<u64>();

        p0.write(!0);
        p1.write(!1);
        p2.write(!2);

        let new = mremap(p1.cast(), 0x3000, 0x5000, MRemapFlags::empty(), None).unwrap();
        assert_eq!(new, ptr.byte_add(0x1000));

        assert_eq!(try_read(p0), Some(!0)); // untouched
        assert_eq!(try_read(p1), Some(!1)); // untouched
        assert_eq!(try_read(p2), Some(!2)); // untouched

        let new = mremap(p0.cast(), 0x6000, 0x7000, MRemapFlags::empty(), None).unwrap();
        assert_eq!(new, ptr);

        assert_eq!(try_read(p0), Some(!0)); // untouched
        assert_eq!(try_read(p1), Some(!1)); // untouched
        assert_eq!(try_read(p2), Some(!2)); // untouched
    }
}

#[test]
fn mremap_several_private_grow() {
    unsafe {
        let len = NonZeroUsize::new(0x9000).unwrap();
        let ptr = mmap_anonymous_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();

        let p0 = ptr.cast::<u64>();
        let p1 = ptr.byte_add(0x1000).cast::<u64>();
        let p2 = ptr.byte_add(0x2000).cast::<u64>();

        p0.write(!0);
        p1.write(!1);
        p2.write(!2);

        let len = NonZeroUsize::new(0x1000).unwrap();
        mmap_anonymous(
            Some(p2.addr()),
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
        )
        .unwrap();

        p2.write(!0x202);

        let new = mremap(p0.cast(), 0x3000, 0x4000, MRemapFlags::MREMAP_MAYMOVE, None).unwrap();
        let new_p0 = new.cast::<u64>();
        let new_p1 = new.byte_add(0x1000).cast::<u64>();
        let new_p2 = new.byte_add(0x2000).cast::<u64>();
        let new_p3 = new.byte_add(0x3000).cast::<u64>();

        assert_eq!(try_read(new_p0), Some(!0));
        assert_eq!(try_read(new_p1), Some(!1));
        assert_eq!(try_read(new_p2), Some(!0x202));
        assert_eq!(try_read(new_p3), Some(0));
    }
}

#[test]
fn mremap_several_private_with_hole() {
    unsafe {
        let len = NonZeroUsize::new(0x3000).unwrap();
        let ptr = mmap_anonymous_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();

        let len = NonZeroUsize::new(0x1000).unwrap();
        mmap_anonymous(
            Some(ptr.byte_add(0x1000).addr()),
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
        )
        .unwrap();

        munmap(ptr.byte_add(0x2000).cast(), 0x1000).unwrap();

        assert_eq!(
            mremap(ptr, 0x3000, 0x4000, MRemapFlags::MREMAP_MAYMOVE, None),
            Err(Errno::EFAULT)
        );
    }
}

#[test]
fn mremap_several_private_shrink() {
    unsafe {
        let len = NonZeroUsize::new(0x4000).unwrap();
        let ptr = mmap_anonymous_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();

        let p0 = ptr.cast::<u64>();
        let p1 = ptr.byte_add(0x1000).cast::<u64>();
        let p2 = ptr.byte_add(0x2000).cast::<u64>();
        let p3 = ptr.byte_add(0x3000).cast::<u64>();

        p0.write(!0);
        p1.write(!1);
        p2.write(!2);
        p3.write(!3);

        let len = NonZeroUsize::new(0x1000).unwrap();
        mmap_anonymous(
            Some(p1.addr()),
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
        )
        .unwrap();

        p1.write(!0x101);

        let new = mremap(p0.cast(), 0x3000, 0x2000, MRemapFlags::empty(), None).unwrap();
        assert_eq!(new, ptr);

        assert_eq!(try_read(p0), Some(!0));
        assert_eq!(try_read(p1), Some(!0x101));
        assert_eq!(try_read(p2), None);
        assert_eq!(try_read(p3), Some(!3));
    }
}

#[test]
fn mremap_private_shared_memfd() {
    unsafe {
        let len = NonZeroUsize::new(0x3000).unwrap();
        let ptr = mmap_anonymous_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();

        let fd = memfd_create("test", MFdFlags::MFD_CLOEXEC).unwrap();
        ftruncate(&fd, 0x1000).unwrap();

        let p1 = ptr.byte_add(0x1000);
        let len = NonZeroUsize::new(0x1000).unwrap();
        let ptr = mmap(
            Some(p1.addr()),
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED | MapFlags::MAP_FIXED,
            &fd,
            0,
        )
        .unwrap();

        assert_eq!(
            mremap(ptr, 0x3000, 0x4000, MRemapFlags::MREMAP_MAYMOVE, None),
            Err(Errno::EFAULT)
        );
    }
}

#[test]
fn mremap_private_private_memfd() {
    unsafe {
        let len = NonZeroUsize::new(0x3000).unwrap();
        let ptr = mmap_anonymous_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();

        let fd = memfd_create("test", MFdFlags::MFD_CLOEXEC).unwrap();
        ftruncate(&fd, 0x1000).unwrap();

        let p1 = ptr.byte_add(0x1000);
        let len = NonZeroUsize::new(0x1000).unwrap();
        let ptr = mmap(
            Some(p1.addr()),
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            &fd,
            0,
        )
        .unwrap();

        assert_eq!(
            mremap(ptr, 0x3000, 0x4000, MRemapFlags::MREMAP_MAYMOVE, None),
            Err(Errno::EFAULT)
        );
    }
}

#[test]
fn mremap_private_memfd_private_memfd() {
    unsafe {
        let fd = memfd_create("test", MFdFlags::MFD_CLOEXEC).unwrap();
        ftruncate(&fd, 0x4000).unwrap();

        let len = NonZeroUsize::new(0x3000).unwrap();
        let ptr = mmap_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE,
            &fd,
            0,
        )
        .unwrap();

        let p1 = ptr.byte_add(0x1000);
        let len = NonZeroUsize::new(0x1000).unwrap();
        let ptr = mmap(
            Some(p1.addr()),
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
            &fd,
            0x1000,
        )
        .unwrap();

        assert_eq!(
            mremap(ptr, 0x3000, 0x4000, MRemapFlags::MREMAP_MAYMOVE, None),
            Err(Errno::EFAULT)
        );
    }
}

#[test]
fn mremap_shared_anon_shared_anon() {
    unsafe {
        let len = NonZeroUsize::new(0x3000).unwrap();
        let ptr = mmap_anonymous(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();

        let p1 = ptr.byte_add(0x1000);
        let len = NonZeroUsize::new(0x1000).unwrap();
        let ptr = mmap_anonymous(
            Some(p1.addr()),
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED | MapFlags::MAP_FIXED | MapFlags::MAP_ANONYMOUS,
        )
        .unwrap();

        assert_eq!(
            mremap(ptr, 0x3000, 0x4000, MRemapFlags::MREMAP_MAYMOVE, None),
            Err(Errno::EFAULT)
        );
    }
}

#[test]
fn mremap_shared_memfd_shared_memfd() {
    unsafe {
        let fd = memfd_create("test", MFdFlags::MFD_CLOEXEC).unwrap();
        ftruncate(&fd, 0x4000).unwrap();

        let len = NonZeroUsize::new(0x3000).unwrap();
        let ptr = mmap_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED,
            &fd,
            0,
        )
        .unwrap();

        let p1 = ptr.byte_add(0x1000);
        let len = NonZeroUsize::new(0x1000).unwrap();
        let ptr = mmap(
            Some(p1.addr()),
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED | MapFlags::MAP_FIXED,
            &fd,
            0x1000,
        )
        .unwrap();

        assert_eq!(
            mremap(ptr, 0x3000, 0x4000, MRemapFlags::MREMAP_MAYMOVE, None),
            Err(Errno::EFAULT)
        );
    }
}

#[test]
fn shared_copy_memfd() {
    unsafe {
        let fd = memfd_create("test", MFdFlags::MFD_CLOEXEC).unwrap();
        ftruncate(&fd, 0x4000).unwrap();

        let len = NonZeroUsize::new(0x4000).unwrap();
        let ptr = mmap_with_guard_pages(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED,
            &fd,
            0,
        )
        .unwrap();

        let p0 = ptr.cast::<u64>();
        let p1 = ptr.byte_add(0x1000).cast::<u64>();
        let p2 = ptr.byte_add(0x2000).cast::<u64>();
        let p3 = ptr.byte_add(0x3000).cast::<u64>();

        p0.write(!0);
        p1.write(!1);
        p2.write(!2);
        p3.write(!3);

        let new_ptr = mremap(ptr, 0, 0x4000, MRemapFlags::MREMAP_MAYMOVE, None).unwrap();

        let new_p0 = new_ptr.cast::<u64>();
        let new_p1 = new_ptr.byte_add(0x1000).cast::<u64>();
        let new_p2 = new_ptr.byte_add(0x2000).cast::<u64>();
        let new_p3 = new_ptr.byte_add(0x3000).cast::<u64>();

        assert_eq!(new_p0.read(), !0);
        assert_eq!(new_p1.read(), !1);
        assert_eq!(new_p2.read(), !2);
        assert_eq!(new_p3.read(), !3);

        new_p0.write(0);
        new_p1.write(1);
        new_p2.write(2);
        new_p3.write(3);

        assert_eq!(new_p0.read(), 0);
        assert_eq!(new_p1.read(), 1);
        assert_eq!(new_p2.read(), 2);
        assert_eq!(new_p3.read(), 3);
    }
}

#[test]
fn shared_copy_anon_private() {
    unsafe {
        let len = NonZeroUsize::new(0x4000).unwrap();
        let ptr = mmap_anonymous(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE,
        )
        .unwrap();

        assert_eq!(
            mremap(ptr, 0, 0x4000, MRemapFlags::MREMAP_MAYMOVE, None),
            Err(Errno::EINVAL)
        );
    }
}

#[test]
fn shared_copy_shared_anon() {
    unsafe {
        let len = NonZeroUsize::new(0x4000).unwrap();
        let ptr = mmap_anonymous(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED,
        )
        .unwrap();

        let p0 = ptr.cast::<u64>();
        let p1 = ptr.byte_add(0x1000).cast::<u64>();
        let p2 = ptr.byte_add(0x2000).cast::<u64>();
        let p3 = ptr.byte_add(0x3000).cast::<u64>();

        p0.write(!0);
        p1.write(!1);
        p2.write(!2);
        p3.write(!3);

        let new_ptr = mremap(ptr, 0, 0x4000, MRemapFlags::MREMAP_MAYMOVE, None).unwrap();
        assert_ne!(new_ptr, ptr);

        let new_p0 = new_ptr.cast::<u64>();
        let new_p1 = new_ptr.byte_add(0x1000).cast::<u64>();
        let new_p2 = new_ptr.byte_add(0x2000).cast::<u64>();
        let new_p3 = new_ptr.byte_add(0x3000).cast::<u64>();

        assert_eq!(new_p0.read(), !0);
        assert_eq!(new_p1.read(), !1);
        assert_eq!(new_p2.read(), !2);
        assert_eq!(new_p3.read(), !3);

        new_p0.write(0);
        new_p1.write(1);
        new_p2.write(2);
        new_p3.write(3);

        assert_eq!(new_p0.read(), 0);
        assert_eq!(new_p1.read(), 1);
        assert_eq!(new_p2.read(), 2);
        assert_eq!(new_p3.read(), 3);
    }
}

#[test]
fn shared_copy_shared_anon_with_offset() {
    unsafe {
        let len = NonZeroUsize::new(0x4000).unwrap();
        let ptr = mmap_anonymous(
            None,
            len,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED,
        )
        .unwrap();

        let p1 = ptr.byte_add(0x1000).cast::<u64>();
        let p2 = ptr.byte_add(0x2000).cast::<u64>();
        let p3 = ptr.byte_add(0x3000).cast::<u64>();

        p1.write(!1);
        p2.write(!2);
        p3.write(!3);

        let new_ptr = mremap(
            ptr.byte_add(0x1000),
            0,
            0x4000,
            MRemapFlags::MREMAP_MAYMOVE,
            None,
        )
        .unwrap();
        assert_ne!(new_ptr, ptr);

        let new_p1 = new_ptr.cast::<u64>();
        let new_p2 = new_ptr.byte_add(0x1000).cast::<u64>();
        let new_p3 = new_ptr.byte_add(0x2000).cast::<u64>();
        let new_p4 = new_ptr.byte_add(0x3000).cast::<u64>();

        assert_eq!(try_read(new_p4), None);

        assert_eq!(new_p1.read(), !1);
        assert_eq!(new_p2.read(), !2);
        assert_eq!(new_p3.read(), !3);

        new_p1.write(1);
        new_p2.write(2);
        new_p3.write(3);

        assert_eq!(new_p1.read(), 1);
        assert_eq!(new_p2.read(), 2);
        assert_eq!(new_p3.read(), 3);
    }
}

#[test]
fn remap_private_anon_different_permissions() {
    unsafe {
        let length = NonZeroUsize::new(0x4000).unwrap();
        let ptr = mmap_anonymous_with_guard_pages(
            None,
            length,
            ProtFlags::empty(),
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
        )
        .unwrap();

        mprotect(ptr.byte_add(0x1000), 0x1000, ProtFlags::PROT_READ).unwrap();
        mprotect(
            ptr.byte_add(0x2000),
            0x1000,
            ProtFlags::PROT_READ | ProtFlags::PROT_EXEC,
        )
        .unwrap();
        mprotect(
            ptr.byte_add(0x3000),
            0x1000,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        )
        .unwrap();

        assert_eq!(
            mremap(ptr, 0x4000, 0x5000, MRemapFlags::MREMAP_MAYMOVE, None),
            Err(Errno::EFAULT)
        );
        assert_eq!(
            mremap(ptr, 0x2000, 0x5000, MRemapFlags::MREMAP_MAYMOVE, None),
            Err(Errno::EFAULT)
        );
        assert_eq!(
            mremap(
                ptr.byte_add(0x1000),
                0x2000,
                0x5000,
                MRemapFlags::MREMAP_MAYMOVE,
                None
            ),
            Err(Errno::EFAULT)
        );
        assert_eq!(
            mremap(
                ptr.byte_add(0x2000),
                0x2000,
                0x5000,
                MRemapFlags::MREMAP_MAYMOVE,
                None
            ),
            Err(Errno::EFAULT)
        );
    }
}
