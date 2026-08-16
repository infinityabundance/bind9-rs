//! The fixed-size power-of-2 circular queue (`libmy/my_queue.{h,mb,mutex}.c`).
//!
//! The iothr's default SPSC queue is the memory-barrier variant; the MPSC
//! queue is mutex-protected.  The *observable* queue contract (insert/remove
//! success, the reported remaining `space`/`count`, and the wrap-around
//! arithmetic) is identical between the two implementations, so this module
//! conserves the shared semantics with a `Mutex`-protected buffer: the same
//! `q_space`/`q_count` formulas (`(tail - (head + 1)) & (size - 1)` /
//! `(head - tail) & (size - 1)`, unsigned wrap-around), the same
//! power-of-2/`num_elems < 2` rejection in init, and the same
//! insert-then-decrement space reporting.
//!
//! The element type is erased (`T`) rather than raw bytes; the slot count and
//! the head/tail arithmetic match the C exactly, which is what the court
//! observes through `fstrm_iothr_submit`'s `space == queue_notify_threshold`
//! wakeup and the `again`/`success` return taxonomy.

/// `struct my_queue` (my_queue_mutex.c): the head/tail indices are `u32`
/// like the C's `unsigned`; all index arithmetic wraps.
pub struct Queue<T> {
    data: Vec<Option<T>>,
    num_elems: u32,
    head: u32,
    tail: u32,
}

impl<T> Queue<T> {
    /// `my_queue_init` (my_queue_mutex.c): NULL (None) when `num_elems < 2`
    /// or not a power of 2.
    pub fn new(num_elems: u32) -> Option<Queue<T>> {
        if num_elems < 2 || ((num_elems - 1) & num_elems) != 0 {
            return None;
        }
        Some(Queue {
            data: (0..num_elems).map(|_| None).collect(),
            num_elems,
            head: 0,
            tail: 0,
        })
    }

    /// `q_space`: `(tail - (head + 1)) & (size - 1)`.
    #[must_use]
    pub fn space(&self) -> u32 {
        self.tail.wrapping_sub(self.head.wrapping_add(1)) & (self.num_elems - 1)
    }

    /// `q_count`: `(head - tail) & (size - 1)`.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.head.wrapping_sub(self.tail) & (self.num_elems - 1)
    }

    /// `my_queue_insert`: `Ok(space)` with the space remaining *after* the
    /// insert (the C decrements the pre-insert space), `Err(())` when full.
    pub fn insert(&mut self, item: T) -> Result<u32, ()> {
        let space = self.space();
        if space >= 1 {
            self.data[self.head as usize] = Some(item);
            self.head = (self.head + 1) & (self.num_elems - 1);
            return Ok(space - 1);
        }
        Err(())
    }

    /// `my_queue_remove`: `Ok((item, count))` with the count remaining *after*
    /// the remove, `Err(())` when empty.
    pub fn remove(&mut self) -> Result<(T, u32), ()> {
        let count = self.count();
        if count >= 1 {
            let item = self.data[self.tail as usize].take().unwrap();
            self.tail = (self.tail + 1) & (self.num_elems - 1);
            return Ok((item, count - 1));
        }
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_init_rejects_bad_sizes() {
        assert!(Queue::<u32>::new(0).is_none());
        assert!(Queue::<u32>::new(1).is_none());
        assert!(Queue::<u32>::new(3).is_none());
        assert!(Queue::<u32>::new(6).is_none());
        assert!(Queue::<u32>::new(2).is_some());
        assert!(Queue::<u32>::new(4).is_some());
        assert!(Queue::<u32>::new(512).is_some());
    }

    #[test]
    fn queue_fifo_and_full() {
        let mut q = Queue::new(4).unwrap();
        // space: 4 slots -> 3 usable (head+1 kept free, like the C).
        assert_eq!(q.space(), 3);
        assert_eq!(q.count(), 0);
        assert_eq!(q.insert(10), Ok(2));
        assert_eq!(q.insert(20), Ok(1));
        assert_eq!(q.insert(30), Ok(0));
        assert_eq!(q.insert(40), Err(())); // full
        let (v, c) = q.remove().unwrap();
        assert_eq!(v, 10);
        assert_eq!(c, 2); // 2 of 3 remain
        assert_eq!(q.insert(40), Ok(0));
        let (v, _) = q.remove().unwrap();
        assert_eq!(v, 20);
        let (v, _) = q.remove().unwrap();
        assert_eq!(v, 30);
        let (v, _) = q.remove().unwrap();
        assert_eq!(v, 40);
        assert_eq!(q.remove(), Err(())); // empty
    }

    #[test]
    fn queue_wraparound() {
        // Fill and drain around the 4-slot ring so head/tail wrap.
        let mut q = Queue::new(4).unwrap();
        for i in 0..6u32 {
            let _ = q.insert(i);
            let _ = q.remove();
        }
        // Still functional after wrapping.
        assert_eq!(q.insert(99), Ok(2));
        let (v, _) = q.remove().unwrap();
        assert_eq!(v, 99);
    }
}
