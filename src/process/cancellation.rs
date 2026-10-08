use std::cell::RefCell;
use std::io;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

#[derive(Default)]
struct State {
    first: AtomicI32,
    signals: AtomicUsize,
}

thread_local! {
    static CURRENT: RefCell<Weak<State>> = const { RefCell::new(Weak::new()) };
}

/// Keeps cancellation handlers installed through preflight and final output.
/// Nested scopes on the calling thread share the first cancellation cause.
pub struct CancellationScope {
    state: Arc<State>,
    handlers: Vec<signal_hook::SigId>,
    thread: PhantomData<Rc<()>>,
}

impl CancellationScope {
    /// Installs signal handlers before any owned process can be started.
    ///
    /// # Errors
    /// Returns an error if signal handler installation fails.
    pub fn enter() -> io::Result<Self> {
        if let Some(state) = CURRENT.with(|current| current.borrow().upgrade()) {
            return Ok(Self {
                state,
                handlers: Vec::new(),
                thread: PhantomData,
            });
        }
        let mut scope = Self {
            state: Arc::new(State::default()),
            handlers: Vec::new(),
            thread: PhantomData,
        };
        for signal in [libc::SIGINT, libc::SIGTERM] {
            let state = Arc::clone(&scope.state);
            // SAFETY: Only lock-free atomic operations run in the handler.
            // The scope unregisters both handlers on all exit paths.
            let handler = unsafe {
                signal_hook::low_level::register(signal, move || {
                    let _ =
                        state
                            .first
                            .compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
                    state.signals.fetch_add(1, Ordering::SeqCst);
                })
            }?;
            scope.handlers.push(handler);
        }
        CURRENT.with(|current| *current.borrow_mut() = Arc::downgrade(&scope.state));
        Ok(scope)
    }

    #[must_use]
    pub fn signal(&self) -> Option<i32> {
        match self.state.first.load(Ordering::SeqCst) {
            0 => None,
            signal => Some(signal),
        }
    }

    #[must_use]
    pub fn exit_code(&self) -> Option<u8> {
        self.signal()
            .and_then(|signal| u8::try_from(128 + signal).ok())
    }

    pub(super) fn repeated(&self) -> bool {
        self.state.signals.load(Ordering::SeqCst) > 1
    }
}

impl Drop for CancellationScope {
    fn drop(&mut self) {
        for handler in self.handlers.drain(..) {
            signal_hook::low_level::unregister(handler);
        }
    }
}

pub(super) fn signal() -> Option<i32> {
    CURRENT.with(|current| {
        current.borrow().upgrade().and_then(|state| {
            let signal = state.first.load(Ordering::SeqCst);
            (signal != 0).then_some(signal)
        })
    })
}

pub(super) fn repeated() -> bool {
    CURRENT.with(|current| {
        current
            .borrow()
            .upgrade()
            .is_some_and(|state| state.signals.load(Ordering::SeqCst) > 1)
    })
}

fn duplicate(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl validates the source descriptor and returns a new owner.
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Successful F_DUPFD_CLOEXEC returned a new, unowned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

struct SignalMask(libc::sigset_t);

impl SignalMask {
    fn block_ttou() -> io::Result<Self> {
        let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: Both masks are writable, and sigemptyset initializes mask
        // before it is used by sigaddset and pthread_sigmask.
        let result = unsafe {
            libc::sigemptyset(mask.as_mut_ptr());
            libc::sigaddset(mask.as_mut_ptr(), libc::SIGTTOU);
            libc::pthread_sigmask(libc::SIG_BLOCK, mask.as_ptr(), previous.as_mut_ptr())
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        // SAFETY: Successful pthread_sigmask initialized the previous mask.
        Ok(Self(unsafe { previous.assume_init() }))
    }
}

impl Drop for SignalMask {
    fn drop(&mut self) {
        // SAFETY: Restore this thread's valid saved mask, not a global handler.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &raw const self.0, std::ptr::null_mut())
        };
    }
}

pub(super) struct TerminalForeground {
    terminal: OwnedFd,
    original: i32,
    child: i32,
    modes: libc::termios,
    active: bool,
}

impl TerminalForeground {
    pub(super) fn handoff(child: i32) -> io::Result<Option<Self>> {
        // SAFETY: These queries retain no pointers and validate fd 0.
        let original = unsafe { libc::getpgrp() };
        if unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) } != original {
            return Ok(None);
        }
        let terminal = duplicate(libc::STDIN_FILENO)?;
        let _mask = SignalMask::block_ttou()?;
        // Recheck after blocking SIGTTOU: never take another group's terminal.
        // SAFETY: terminal owns a live descriptor throughout these operations.
        if unsafe { libc::tcgetpgrp(terminal.as_raw_fd()) } != original {
            return Ok(None);
        }
        let mut modes = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: terminal is owned and modes is writable for tcgetattr.
        if unsafe { libc::tcgetattr(terminal.as_raw_fd(), modes.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Successful tcgetattr initialized the saved terminal modes.
        let modes = unsafe { modes.assume_init() };
        // SAFETY: Recheck ownership immediately before handing off the PTY.
        if unsafe { libc::tcgetpgrp(terminal.as_raw_fd()) } != original {
            return Ok(None);
        }
        if unsafe { libc::tcsetpgrp(terminal.as_raw_fd(), child) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self {
            terminal,
            original,
            child,
            modes,
            active: true,
        }))
    }

    pub(super) fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        let _mask = SignalMask::block_ttou()?;
        // SAFETY: The descriptor is owned and the caller still pins the child's
        // group identity. Restore only if nobody else acquired foreground.
        if unsafe { libc::tcgetpgrp(self.terminal.as_raw_fd()) } == self.child {
            // SAFETY: Restore saved modes while the child still owns foreground,
            // with SIGTTOU blocked. TCSANOW neither waits for nor discards I/O.
            if unsafe {
                libc::tcsetattr(
                    self.terminal.as_raw_fd(),
                    libc::TCSANOW,
                    &raw const self.modes,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: Recheck after restoring modes so another owner keeps
            // foreground if it acquired the terminal during that operation.
            if unsafe { libc::tcgetpgrp(self.terminal.as_raw_fd()) } == self.child
                && unsafe { libc::tcsetpgrp(self.terminal.as_raw_fd(), self.original) } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for TerminalForeground {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Cancellation-aware output for the executable's owned stdout/stderr fds.
/// Arbitrary user-provided `Write` implementations cannot promise this bound.
pub struct CliWriter(OwnedFd);

impl CliWriter {
    #[must_use]
    pub fn new(fd: OwnedFd) -> Self {
        Self(fd)
    }

    /// Duplicates stdout without changing its file-status flags.
    ///
    /// # Errors
    /// Returns an error if the descriptor cannot be duplicated.
    pub fn stdout() -> io::Result<Self> {
        duplicate(libc::STDOUT_FILENO).map(Self)
    }

    /// Duplicates stderr without changing its file-status flags.
    ///
    /// # Errors
    /// Returns an error if the descriptor cannot be duplicated.
    pub fn stderr() -> io::Result<Self> {
        duplicate(libc::STDERR_FILENO).map(Self)
    }
}

struct FileFlags {
    fd: RawFd,
    previous: i32,
}

impl FileFlags {
    fn nonblocking(fd: RawFd) -> io::Result<Self> {
        // SAFETY: The caller retains the fd owner until this guard is dropped.
        let previous = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if previous < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFL, previous | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, previous })
    }
}

impl Drop for FileFlags {
    fn drop(&mut self) {
        // SAFETY: The enclosing write still retains the descriptor's owner.
        unsafe { libc::fcntl(self.fd, libc::F_SETFL, self.previous) };
    }
}

fn check_output_cancellation() -> io::Result<()> {
    if signal().is_some() {
        // Interrupted would be silently retried by Write::write_all.
        Err(io::Error::other("output cancelled"))
    } else {
        Ok(())
    }
}

impl io::Write for CliWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        check_output_cancellation()?;
        let fd = self.0.as_raw_fd();
        // dup shares file-status flags. Change them only during a CLI write,
        // never throughout recording when workloads may inherit stdout.
        let _flags = FileFlags::nonblocking(fd)?;
        loop {
            check_output_cancellation()?;
            // SAFETY: bytes remains readable, and this writer owns fd.
            let count = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len().min(65536)) };
            if count >= 0 {
                return usize::try_from(count).map_err(io::Error::other);
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => {}
                _ => return Err(error),
            }
            let mut descriptor = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: poll borrows this initialized descriptor for the call.
            if unsafe { libc::poll(&raw mut descriptor, 1, 20) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        check_output_cancellation()
    }
}
