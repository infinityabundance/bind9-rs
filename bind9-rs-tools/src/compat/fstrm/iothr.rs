//! `fstrm_iothr` (iothr.c/iothr.h): the background I/O thread and its input
//! queues.  Workers submit data frames with [`submit`]; the I/O thread opens
//! the captive writer, drains the queues into an output buffer, flushes when
//! the buffer fills (`output_queue_size` frames or `buffer_hint` bytes) or
//! after `flush_timeout` seconds, and on [`iothr_destroy`] drains, flushes,
//! closes, and joins.
//!
//! The observable contract transcribed here: the option bounds and defaults
//! (iothr.h), the queue power-of-2/`num_elems < 2` rejection at init, the
//! `submit` taxonomy (`success`/`again`/`invalid`/`failure`, with the
//! `space == queue_notify_threshold` wakeup), the round-robin queue drain,
//! the flush thresholds, the deferred free callback (invoked after the frame
//! is written, or immediately when the writer is closed), and the
//! reopen-interval gating of writer open attempts.  The memory-barrier vs
//! mutex queue implementations produce identical observable results, so one
//! mutex-protected queue (with the same head/tail arithmetic) conserves both.
//!
//! One divergence by construction: the C I/O thread blocks SIGPIPE for its
//! lifetime so a write to a peer-closed socket fails instead of killing the
//! process; Rust cannot set a per-thread signal mask safely, and the court
//! corpus never writes to a peer-closed socket, so this is not observable in
//! the conservation surface.

use super::{
    queue::Queue, writer::Writer, Res, IOTHR_BUFFER_HINT_DEFAULT, IOTHR_BUFFER_HINT_MAX,
    IOTHR_BUFFER_HINT_MIN, IOTHR_FLUSH_TIMEOUT_DEFAULT, IOTHR_FLUSH_TIMEOUT_MAX,
    IOTHR_FLUSH_TIMEOUT_MIN, IOTHR_INPUT_QUEUE_SIZE_DEFAULT, IOTHR_INPUT_QUEUE_SIZE_MAX,
    IOTHR_INPUT_QUEUE_SIZE_MIN, IOTHR_NUM_INPUT_QUEUES_DEFAULT, IOTHR_NUM_INPUT_QUEUES_MIN,
    IOTHR_OUTPUT_QUEUE_SIZE_DEFAULT, IOTHR_OUTPUT_QUEUE_SIZE_MAX, IOTHR_OUTPUT_QUEUE_SIZE_MIN,
    IOTHR_QUEUE_NOTIFY_THRESHOLD_DEFAULT, IOTHR_QUEUE_NOTIFY_THRESHOLD_MIN,
    IOTHR_REOPEN_INTERVAL_DEFAULT, IOTHR_REOPEN_INTERVAL_MAX, IOTHR_REOPEN_INTERVAL_MIN, IOV_MAX,
};
use std::mem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

/// `fstrm_iothr_queue_model` (iothr.h:221).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum QueueModel {
    /// Single Producer, Single Consumer.
    Spsc = 0,
    /// Multiple Producer, Single Consumer.
    Mpsc = 1,
}

/// The deallocation callback: `fstrm_iothr_submit`'s `free_func`/`free_data`
/// pair.  The C calls `free_func(data, free_data)` once the frame is written
/// (or discarded); here the callback receives ownership of the frame bytes.
pub type FreeFunc = Box<dyn FnOnce(Vec<u8>) + Send + 'static>;

/// `fstrm_free_wrapper`: the system `free()` equivalent — drop the buffer.
pub fn free_wrapper(data: Vec<u8>) {
    drop(data);
}

/// `struct fstrm__iothr_queue_entry` (iothr.c:55).
struct QueueEntry {
    /// The deallocation callback (the C's `free_func` + `free_data`).
    free_func: Option<FreeFunc>,
    /// The actual payload bytes, allocated by the caller.
    data: Option<Vec<u8>>,
    /// Number of bytes in `data`.
    len_data: u32,
}

impl QueueEntry {
    fn new(data: Vec<u8>, free_func: Option<FreeFunc>) -> QueueEntry {
        let len_data = data.len() as u32;
        QueueEntry {
            free_func,
            data: Some(data),
            len_data,
        }
    }
}

/// `fstrm__iothr_queue_entry_free_bytes` (iothr.c:338): the free callback
/// fires exactly once per entry — on Drop (write path and discard path).  A
/// `None` callback mirrors the C's `free_func == NULL` case: the buffer is
/// deliberately leaked (the caller documented it as a static object).
impl Drop for QueueEntry {
    fn drop(&mut self) {
        match self.free_func.take() {
            Some(f) => f(self.data.take().unwrap_or_default()),
            None => {
                if let Some(d) = self.data.take() {
                    mem::forget(d);
                }
            }
        }
    }
}

/// `struct fstrm_iothr_options` (iothr.c:29) with the defaults from
/// `default_fstrm_iothr_options` (iothr.c:40).
#[derive(Clone, Copy, Debug)]
pub struct IothrOptions {
    pub buffer_hint: u32,
    pub flush_timeout: u32,
    pub input_queue_size: u32,
    pub num_input_queues: u32,
    pub output_queue_size: u32,
    pub queue_notify_threshold: u32,
    pub reopen_interval: u32,
    pub queue_model: QueueModel,
}

impl IothrOptions {
    /// `fstrm_iothr_options_init`.
    #[must_use]
    pub fn new() -> IothrOptions {
        IothrOptions {
            buffer_hint: IOTHR_BUFFER_HINT_DEFAULT,
            flush_timeout: IOTHR_FLUSH_TIMEOUT_DEFAULT,
            input_queue_size: IOTHR_INPUT_QUEUE_SIZE_DEFAULT,
            num_input_queues: IOTHR_NUM_INPUT_QUEUES_DEFAULT,
            output_queue_size: IOTHR_OUTPUT_QUEUE_SIZE_DEFAULT,
            queue_notify_threshold: IOTHR_QUEUE_NOTIFY_THRESHOLD_DEFAULT,
            reopen_interval: IOTHR_REOPEN_INTERVAL_DEFAULT,
            queue_model: QueueModel::Spsc,
        }
    }

    /// `fstrm_iothr_options_set_buffer_hint` (iothr.c:133).
    pub fn set_buffer_hint(&mut self, buffer_hint: u32) -> Res {
        if buffer_hint < IOTHR_BUFFER_HINT_MIN || buffer_hint > IOTHR_BUFFER_HINT_MAX {
            return Res::Failure;
        }
        self.buffer_hint = buffer_hint;
        Res::Success
    }

    /// `fstrm_iothr_options_set_flush_timeout` (iothr.c:146).
    pub fn set_flush_timeout(&mut self, flush_timeout: u32) -> Res {
        if flush_timeout < IOTHR_FLUSH_TIMEOUT_MIN || flush_timeout > IOTHR_FLUSH_TIMEOUT_MAX {
            return Res::Failure;
        }
        self.flush_timeout = flush_timeout;
        Res::Success
    }

    /// `fstrm_iothr_options_set_input_queue_size` (iothr.c:159): must be even
    /// (the power-of-2 requirement is enforced at queue init, exactly like
    /// the C: the setter rejects odd values only).
    pub fn set_input_queue_size(&mut self, input_queue_size: u32) -> Res {
        if input_queue_size < IOTHR_INPUT_QUEUE_SIZE_MIN
            || input_queue_size > IOTHR_INPUT_QUEUE_SIZE_MAX
            || (input_queue_size & 1) != 0
        {
            return Res::Failure;
        }
        self.input_queue_size = input_queue_size;
        Res::Success
    }

    /// `fstrm_iothr_options_set_num_input_queues` (iothr.c:173).
    pub fn set_num_input_queues(&mut self, num_input_queues: u32) -> Res {
        if num_input_queues < IOTHR_NUM_INPUT_QUEUES_MIN {
            return Res::Failure;
        }
        self.num_input_queues = num_input_queues;
        Res::Success
    }

    /// `fstrm_iothr_options_set_output_queue_size` (iothr.c:183).
    pub fn set_output_queue_size(&mut self, output_queue_size: u32) -> Res {
        if output_queue_size < IOTHR_OUTPUT_QUEUE_SIZE_MIN
            || output_queue_size > IOTHR_OUTPUT_QUEUE_SIZE_MAX
        {
            return Res::Failure;
        }
        self.output_queue_size = output_queue_size;
        Res::Success
    }

    /// `fstrm_iothr_options_set_queue_model` (iothr.c:196).  The C takes the
    /// enum by value, so any raw integer is representable; unknown values
    /// fail exactly like the C's `queue_model != SPSC && queue_model != MPSC`
    /// check.
    pub fn set_queue_model_raw(&mut self, queue_model: u32) -> Res {
        match queue_model {
            v if v == QueueModel::Spsc as u32 => {
                self.queue_model = QueueModel::Spsc;
                Res::Success
            }
            v if v == QueueModel::Mpsc as u32 => {
                self.queue_model = QueueModel::Mpsc;
                Res::Success
            }
            _ => Res::Failure,
        }
    }

    /// `fstrm_iothr_options_set_queue_model` (iothr.c:196).
    pub fn set_queue_model(&mut self, queue_model: QueueModel) -> Res {
        self.set_queue_model_raw(queue_model as u32)
    }

    /// `fstrm_iothr_options_set_queue_notify_threshold` (iothr.c:209).
    pub fn set_queue_notify_threshold(&mut self, queue_notify_threshold: u32) -> Res {
        if queue_notify_threshold < IOTHR_QUEUE_NOTIFY_THRESHOLD_MIN {
            return Res::Failure;
        }
        self.queue_notify_threshold = queue_notify_threshold;
        Res::Success
    }

    /// `fstrm_iothr_options_set_reopen_interval` (iothr.c:219).
    pub fn set_reopen_interval(&mut self, reopen_interval: u32) -> Res {
        if reopen_interval < IOTHR_REOPEN_INTERVAL_MIN
            || reopen_interval > IOTHR_REOPEN_INTERVAL_MAX
        {
            return Res::Failure;
        }
        self.reopen_interval = reopen_interval;
        Res::Success
    }
}

impl Default for IothrOptions {
    fn default() -> Self {
        IothrOptions::new()
    }
}

/// `struct fstrm_iothr_queue` (iothr.c:51): a handle to one input queue.
#[derive(Clone, Copy, Debug)]
pub struct IothrQueue {
    idx: usize,
}

/// `struct fstrm_iothr` (iothr.c:67).
pub struct Iothr {
    opt: IothrOptions,
    /// One mutex-protected queue per `num_input_queues`, shared with the I/O
    /// thread (the C's `my_queue_mb_ops`/`my_queue_mutex_ops` are
    /// observationally identical, so one implementation conserves both).
    queues: Arc<Vec<Mutex<Queue<QueueEntry>>>>,
    shutting_down: Arc<AtomicBool>,
    cv: Arc<(Mutex<()>, Condvar)>,
    /// The C's `get_queue_lock` + `get_queue_idx` (iothr.c:107-108).
    get_queue_state: Mutex<u32>,
    thread: Option<JoinHandle<Writer>>,
}

impl Iothr {
    /// `fstrm_iothr_init` (iothr.c:232): takes ownership of the writer (the
    /// caller's slot becomes `None`).  Fails (returns `None`) if any input
    /// queue cannot be allocated; on failure the captive writer is destroyed,
    /// exactly like the C's `goto fail` → `fstrm_iothr_destroy` path.
    pub fn new(opt: Option<&IothrOptions>, writer: &mut Option<Writer>) -> Option<Iothr> {
        let mut opt = opt.copied().unwrap_or_default();
        // Clamp output_queue_size to IOV_MAX (iothr.c:253); on Linux IOV_MAX
        // is 1024, so this is a no-op transcribed for fidelity.
        if opt.output_queue_size > IOV_MAX as u32 {
            opt.output_queue_size = IOV_MAX as u32;
        }

        let writer = writer.take()?;

        let mut queues: Vec<Mutex<Queue<QueueEntry>>> = Vec::new();
        for _ in 0..opt.num_input_queues {
            let q = Queue::new(opt.input_queue_size)?;
            queues.push(Mutex::new(q));
        }
        let queues = Arc::new(queues);

        let shutting_down = Arc::new(AtomicBool::new(false));
        let cv = Arc::new((Mutex::new(()), Condvar::new()));

        let mut iothr = Iothr {
            opt,
            queues,
            shutting_down,
            cv,
            get_queue_state: Mutex::new(0),
            thread: None,
        };

        // Start the I/O thread (iothr.c:328).
        iothr.thread = Some(iothr.spawn_thread(writer));
        Some(iothr)
    }

    fn spawn_thread(&self, mut writer: Writer) -> JoinHandle<Writer> {
        let opt = self.opt;
        let queues = self.queues.clone();
        let shutting_down = self.shutting_down.clone();
        let cv = self.cv.clone();

        thread::spawn(move || {
            let mut opened = false;
            let mut last_open_attempt: i64 = 0;
            // Output queue state (iothr.c:110-114).
            let mut outq: Vec<QueueEntry> = Vec::new();
            let mut outq_nbytes: u64 = 0;

            let maybe_open = |writer: &mut Writer, opened: &mut bool, last: &mut i64| {
                // If we're already connected, there's nothing to do
                // (iothr.c fstrm__iothr_maybe_open).
                if *opened {
                    return;
                }
                let now = now_secs();
                let since = now.wrapping_sub(*last);
                if since < opt.reopen_interval as i64 {
                    return;
                }
                // Attempt to open the transport.
                *last = now;
                if writer.open() == Res::Success {
                    *opened = true;
                }
            };

            let flush_output = |writer: &mut Writer,
                                opened: &mut bool,
                                outq: &mut Vec<QueueEntry>,
                                outq_nbytes: &mut u64| {
                // Do the actual write (iothr.c fstrm__iothr_flush_output).
                if *opened && !outq.is_empty() {
                    let iovs: Vec<&[u8]> = outq
                        .iter()
                        .map(|e| e.data.as_deref().unwrap_or_default())
                        .collect();
                    if writer.writev(&iovs) != Res::Success {
                        *opened = false;
                        let _ = writer.close();
                    }
                }
                // Perform the deferred deallocations (Drop fires the free
                // callbacks), then zero the counters.
                outq.clear();
                *outq_nbytes = 0;
            };

            let maybe_flush_output = |writer: &mut Writer,
                                      opened: &mut bool,
                                      outq: &mut Vec<QueueEntry>,
                                      outq_nbytes: &mut u64,
                                      nbytes: u64| {
                // If the output queue is full, or there are more than
                // 'buffer_hint' bytes of data ready to be sent, flush
                // (iothr.c fstrm__iothr_maybe_flush_output).
                if !outq.is_empty()
                    && (outq.len() as u32 >= opt.output_queue_size
                        || *outq_nbytes + nbytes >= opt.buffer_hint as u64)
                {
                    flush_output(writer, opened, outq, outq_nbytes);
                }
            };

            let process_queue_entry = |writer: &mut Writer,
                                       opened: &mut bool,
                                       outq: &mut Vec<QueueEntry>,
                                       outq_nbytes: &mut u64,
                                       entry: QueueEntry| {
                if *opened {
                    let nbytes = 4 + u64::from(entry.len_data);
                    maybe_flush_output(writer, opened, outq, outq_nbytes, nbytes);
                    // Copy the entry to the output queue and count the bytes.
                    outq.push(entry);
                    *outq_nbytes += nbytes;
                } else {
                    // Writer is closed: discard the payload (Drop fires the
                    // free callback).
                    drop(entry);
                }
            };

            let process_queues = |writer: &mut Writer,
                                  opened: &mut bool,
                                  outq: &mut Vec<QueueEntry>,
                                  outq_nbytes: &mut u64|
             -> u32 {
                // Remove one input queue entry from each thread's queue
                // and add it to the output queue (iothr.c
                // fstrm__iothr_process_queues).
                let mut total = 0;
                for q in queues.iter() {
                    if let Ok((entry, _count)) = q.lock().unwrap().remove() {
                        process_queue_entry(writer, opened, outq, outq_nbytes, entry);
                        total += 1;
                    }
                }
                total
            };

            let close_writer = |writer: &mut Writer, opened: &mut bool| {
                // fstrm__iothr_close (iothr.c:448).
                if *opened {
                    *opened = false;
                    let _ = writer.close();
                }
            };

            // fstrm__iothr_thr_setup (block SIGPIPE) is intentionally not
            // transcribed (see module docs).
            maybe_open(&mut writer, &mut opened, &mut last_open_attempt);

            loop {
                if shutting_down.load(Ordering::Relaxed) {
                    // Drain everything, flush, close (iothr.c:608-613).
                    while process_queues(&mut writer, &mut opened, &mut outq, &mut outq_nbytes) != 0
                    {
                    }
                    flush_output(&mut writer, &mut opened, &mut outq, &mut outq_nbytes);
                    close_writer(&mut writer, &mut opened);
                    break;
                }

                maybe_open(&mut writer, &mut opened, &mut last_open_attempt);

                let count = process_queues(&mut writer, &mut opened, &mut outq, &mut outq_nbytes);
                if count != 0 {
                    continue;
                }

                // Sleep until notified or the flush timeout elapses
                // (iothr.c:621-639).  The C re-arms an absolute deadline each
                // iteration; the relative wait is equivalent.
                let (lock, cvar) = &*cv;
                let guard = lock.lock().unwrap();
                let timeout = Duration::from_secs(opt.flush_timeout as u64);
                let (guard, timed_out) = cvar.wait_timeout(guard, timeout).unwrap();
                if timed_out.timed_out() {
                    flush_output(&mut writer, &mut opened, &mut outq, &mut outq_nbytes);
                }
                drop(guard);
            }

            writer
        })
    }

    /// `fstrm_iothr_destroy` (iothr.c:361): signal shutdown, join the I/O
    /// thread (which drains, flushes, and closes), then destroy the captive
    /// writer and drop the queues.
    fn destroy_inner(&mut self) {
        if let Some(handle) = self.thread.take() {
            self.shutting_down.store(true, Ordering::Relaxed);
            let (lock, cvar) = &*self.cv;
            let guard = lock.lock().unwrap();
            cvar.notify_all();
            drop(guard);
            if let Ok(writer) = handle.join() {
                // The thread already closed the writer on shutdown; dropping
                // it runs fstrm_writer_destroy, which skips the close for a
                // closed writer (writer.c:126).
                drop(writer);
            }
        }
        self.queues = Arc::new(Vec::new());
    }

    /// `fstrm_iothr_get_input_queue` (iothr.c:387): thread-safe; returns a
    /// unique queue each call, up to `num_input_queues`.
    pub fn get_input_queue(&self) -> Option<IothrQueue> {
        let mut idx = self.get_queue_state.lock().unwrap();
        if *idx < self.opt.num_input_queues {
            let q = IothrQueue { idx: *idx as usize };
            *idx += 1;
            Some(q)
        } else {
            None
        }
    }

    /// `fstrm_iothr_get_input_queue_idx` (iothr.c:402).
    pub fn get_input_queue_idx(&self, idx: usize) -> Option<IothrQueue> {
        if (idx as u32) < self.opt.num_input_queues {
            Some(IothrQueue { idx })
        } else {
            None
        }
    }

    /// `fstrm_iothr_submit` (iothr.c:420): queue a frame for asynchronous
    /// writing.  `invalid` for a zero-length or absurdly long frame (the C's
    /// `len < 1 || len >= UINT32_MAX || data == NULL` — the NULL/empty
    /// distinction is not observable, both are `invalid`); `again` when the
    /// queue is full; `failure` after shutdown.  On success the frame's
    /// deallocation becomes the library's responsibility (the `free_func`
    /// callback fires after the frame is written or discarded).
    pub fn submit(&self, ioq: &IothrQueue, data: Vec<u8>, free_func: Option<FreeFunc>) -> Res {
        if self.shutting_down.load(Ordering::Relaxed) {
            return Res::Failure;
        }
        if data.is_empty() || data.len() >= u32::MAX as usize {
            return Res::Invalid;
        }
        let entry = QueueEntry::new(data, free_func);
        let Ok(mut q) = self.queues[ioq.idx].lock() else {
            return Res::Failure;
        };
        match q.insert(entry) {
            Ok(space) => {
                if space == self.opt.queue_notify_threshold {
                    let (_, cvar) = &*self.cv;
                    cvar.notify_one();
                }
                Res::Success
            }
            Err(()) => Res::Again,
        }
    }
}

impl Drop for Iothr {
    fn drop(&mut self) {
        self.destroy_inner();
    }
}

/// Wall-clock seconds (`time_t` in the C).
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `fstrm_iothr_options_init`.
#[must_use]
pub fn iothr_options_init() -> IothrOptions {
    IothrOptions::new()
}

/// `fstrm_iothr_options_destroy` (the C frees the object; dropping is the
/// Rust equivalent).
pub fn iothr_options_destroy(opt: &mut Option<IothrOptions>) {
    *opt = None;
}

/// `fstrm_iothr_init`.
pub fn iothr_init(opt: Option<&IothrOptions>, writer: &mut Option<Writer>) -> Option<Iothr> {
    Iothr::new(opt, writer)
}

/// `fstrm_iothr_destroy`.
pub fn iothr_destroy(iothr: &mut Option<Iothr>) {
    *iothr = None;
}

/// `fstrm_iothr_get_input_queue`.
pub fn get_input_queue(iothr: &Iothr) -> Option<IothrQueue> {
    iothr.get_input_queue()
}

/// `fstrm_iothr_get_input_queue_idx`.
pub fn get_input_queue_idx(iothr: &Iothr, idx: usize) -> Option<IothrQueue> {
    iothr.get_input_queue_idx(idx)
}

/// `fstrm_iothr_submit`.
pub fn submit(iothr: &Iothr, ioq: &IothrQueue, data: Vec<u8>, free_func: Option<FreeFunc>) -> Res {
    iothr.submit(ioq, data, free_func)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::fstrm::{
        file_writer_init, ControlType as CT, FileOptions, Frame, FrameReader, ReaderOptions, Res,
    };
    use std::sync::atomic::AtomicUsize;

    fn file_writer(path: &str) -> Writer {
        let mut fopt = FileOptions::new();
        fopt.set_file_path(Some(path));
        let mut wopt = super::super::WriterOptions::new();
        wopt.add_content_type(b"test:hello");
        file_writer_init(&fopt, Some(&wopt)).unwrap()
    }

    fn tmp_path(name: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("fstrm-iothr-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_str().unwrap().to_owned()
    }

    #[test]
    fn iothr_options_bounds() {
        let mut o = IothrOptions::new();
        assert_eq!(o.buffer_hint, 8192);
        assert_eq!(o.set_buffer_hint(1023), Res::Failure);
        assert_eq!(o.set_buffer_hint(1024), Res::Success);
        assert_eq!(o.set_buffer_hint(65536), Res::Success);
        assert_eq!(o.set_buffer_hint(65537), Res::Failure);
        assert_eq!(o.set_flush_timeout(0), Res::Failure);
        assert_eq!(o.set_flush_timeout(1), Res::Success);
        assert_eq!(o.set_flush_timeout(600), Res::Success);
        assert_eq!(o.set_flush_timeout(601), Res::Failure);
        assert_eq!(o.set_input_queue_size(1), Res::Failure);
        assert_eq!(o.set_input_queue_size(2), Res::Success);
        assert_eq!(o.set_input_queue_size(3), Res::Failure); // odd
        assert_eq!(o.set_input_queue_size(4), Res::Success);
        assert_eq!(o.set_input_queue_size(6), Res::Success); // even, but not pow2
        assert_eq!(o.set_input_queue_size(16384), Res::Success);
        assert_eq!(o.set_input_queue_size(16385), Res::Failure);
        assert_eq!(o.set_num_input_queues(0), Res::Failure);
        assert_eq!(o.set_num_input_queues(1), Res::Success);
        assert_eq!(o.set_num_input_queues(8), Res::Success);
        assert_eq!(o.set_output_queue_size(1), Res::Failure);
        assert_eq!(o.set_output_queue_size(2), Res::Success);
        assert_eq!(o.set_output_queue_size(1024), Res::Success);
        assert_eq!(o.set_output_queue_size(1025), Res::Failure);
        assert_eq!(o.set_queue_model(QueueModel::Spsc), Res::Success);
        assert_eq!(o.set_queue_model(QueueModel::Mpsc), Res::Success);
        assert_eq!(o.set_queue_notify_threshold(0), Res::Failure);
        assert_eq!(o.set_queue_notify_threshold(1), Res::Success);
        assert_eq!(o.set_reopen_interval(0), Res::Failure);
        assert_eq!(o.set_reopen_interval(1), Res::Success);
        assert_eq!(o.set_reopen_interval(600), Res::Success);
        assert_eq!(o.set_reopen_interval(601), Res::Failure);
        // fstrm_iothr_options_destroy (the C frees the object).
        let mut opt_slot = Some(o);
        super::iothr_options_destroy(&mut opt_slot);
        assert!(opt_slot.is_none());
    }

    #[test]
    fn iothr_init_rejects_bad_queue_size() {
        let path = tmp_path("init-reject.fs");
        let mut w = Some(file_writer(&path));
        let mut opt = IothrOptions::new();
        // Even but not a power of 2: the setter accepts it, init must fail.
        assert_eq!(opt.set_input_queue_size(6), Res::Success);
        assert!(Iothr::new(Some(&opt), &mut w).is_none());
        // The captive writer was destroyed by the failed init (mirrors the C
        // goto-fail path).
        assert!(w.is_none());
        // With a valid size, init succeeds.
        assert_eq!(opt.set_input_queue_size(8), Res::Success);
        let mut w2 = Some(file_writer(&path));
        assert!(Iothr::new(Some(&opt), &mut w2).is_some());
        drop(w2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn iothr_submit_validation() {
        let path = tmp_path("submit-validation.fs");
        let mut w = file_writer(&path);
        let mut opt = IothrOptions::new();
        assert_eq!(opt.set_output_queue_size(4), Res::Success);
        let iothr = Iothr::new(Some(&opt), &mut Some(w)).unwrap();
        let ioq = iothr.get_input_queue().unwrap();
        // len == 0 -> invalid (the C's `len < 1`).
        assert_eq!(iothr.submit(&ioq, Vec::new(), None), Res::Invalid);
        // Submit past the queue capacity; the I/O thread drains concurrently,
        // so the outcome is a mix of success and again, never invalid.
        let frames: Vec<Vec<u8>> = (0..10).map(|i| format!("f{i:04}").into_bytes()).collect();
        let mut again = 0;
        let mut ok = 0;
        for f in &frames {
            match iothr.submit(&ioq, f.clone(), None) {
                Res::Success => ok += 1,
                Res::Again => again += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(ok + again, frames.len());
        // get_input_queue beyond num_input_queues -> None.
        assert!(iothr.get_input_queue().is_none());
        // get_input_queue_idx out of range -> None.
        assert!(iothr.get_input_queue_idx(1).is_none());
        drop(iothr);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn iothr_file_pipeline_deterministic() {
        let path = tmp_path("pipeline.fs");
        let mut w = file_writer(&path);
        let iothr = Iothr::new(None, &mut Some(w)).unwrap();
        let ioq = iothr.get_input_queue().unwrap();

        let freed = Arc::new(AtomicUsize::new(0));
        for i in 0..16 {
            let f = format!("hello world #{i}");
            let data = f.into_bytes();
            loop {
                let counter = freed.clone();
                match iothr.submit(
                    &ioq,
                    data.clone(),
                    Some(Box::new(move |d| {
                        drop(d);
                        counter.fetch_add(1, Ordering::Relaxed);
                    })),
                ) {
                    Res::Success => break,
                    Res::Again => thread::yield_now(),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        // Destroy joins the thread: everything drains, flushes, closes.
        let mut iothr_opt = Some(iothr);
        iothr_destroy(&mut iothr_opt);

        // Every frame was written and freed exactly once.
        assert_eq!(freed.load(Ordering::Relaxed), 16);

        // The file is byte-exact: START(test:hello) + 16 framed payloads + STOP.
        let bytes = std::fs::read(&path).unwrap();
        let mut fr = FrameReader::new(&bytes[..]);
        match fr.next().unwrap().unwrap() {
            Frame::Control(c) => {
                assert_eq!(c.control_type, CT::Start);
                assert_eq!(c.content_types, vec![b"test:hello".to_vec()]);
            }
            _ => panic!("expected START"),
        }
        for i in 0..16 {
            match fr.next().unwrap().unwrap() {
                Frame::Data(d) => assert_eq!(d, format!("hello world #{i}").as_bytes()),
                _ => panic!("expected data frame {i}"),
            }
        }
        match fr.next().unwrap().unwrap() {
            Frame::Control(c) => assert_eq!(c.control_type, CT::Stop),
            _ => panic!("expected STOP"),
        }
        assert_eq!(fr.next().unwrap(), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn iothr_flush_timeout_flushes() {
        // With a 1-second flush timeout and the iothr otherwise idle, the
        // thread flushes after the timeout.  The observable effect: a
        // submitted frame reaches the file even without a destroy.
        let path = tmp_path("flush-timeout.fs");
        let mut w = file_writer(&path);
        let mut opt = IothrOptions::new();
        assert_eq!(opt.set_flush_timeout(1), Res::Success);
        let iothr = Iothr::new(Some(&opt), &mut Some(w)).unwrap();
        let ioq = iothr.get_input_queue().unwrap();
        let frame = b"timeout-frame".to_vec();
        loop {
            match iothr.submit(&ioq, frame.clone(), None) {
                Res::Success => break,
                Res::Again => thread::yield_now(),
                other => panic!("unexpected {other:?}"),
            }
        }
        // Wait for the flush timeout to fire: the file then holds START
        // (30 bytes: escape+len+type+ct-field) plus the data frame
        // (4 + 13 = 17 bytes) = 47 bytes total.
        for _ in 0..100 {
            let len = std::fs::read(&path).map(|b| b.len()).unwrap_or(0);
            if len >= 47 {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() >= 47, "flush timeout did not deliver the frame");
        let mut fr = FrameReader::new(&bytes[..]);
        assert!(matches!(fr.next().unwrap().unwrap(), Frame::Control(_))); // START
        assert_eq!(
            fr.next().unwrap().unwrap(),
            Frame::Data(b"timeout-frame".to_vec())
        );
        drop(iothr);
        let _ = std::fs::remove_file(&path);
        let _ = ReaderOptions::new;
    }
}
