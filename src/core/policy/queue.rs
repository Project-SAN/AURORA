use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Lock-free single-producer/single-consumer ring buffer for no_std runtimes.
///
/// Safety model:
/// - Writers and readers synchronize via atomics; the buffer is mutated through UnsafeCell.
/// - Intended for SPSC usage (one producer + one consumer) or single-threaded polling.
pub struct ValidateQueue<T, const N: usize> {
    head: AtomicUsize,
    tail: AtomicUsize,
    buf: UnsafeCell<[MaybeUninit<T>; N]>,
}

unsafe impl<T: Send, const N: usize> Send for ValidateQueue<T, N> {}
unsafe impl<T: Send, const N: usize> Sync for ValidateQueue<T, N> {}

impl<T, const N: usize> ValidateQueue<T, N> {
    pub const fn new() -> Self {
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buf: UnsafeCell::new([MaybeUninit::uninit(); N]),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.len() >= N
    }

    #[inline]
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }

    /// Pushes a value into the queue. Returns Err(value) if full.
    pub fn push(&self, value: T) -> Result<(), T> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Relaxed);
        if tail.wrapping_sub(head) >= N {
            return Err(value);
        }
        let idx = tail % N;
        unsafe {
            let buf = &mut *self.buf.get();
            buf[idx].as_mut_ptr().write(value);
        }
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Pops a value from the queue. Returns None if empty.
    pub fn pop(&self) -> Option<T> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        let idx = head % N;
        let value = unsafe {
            let buf = &*self.buf.get();
            buf[idx].assume_init_read()
        };
        self.head.store(head.wrapping_add(1), Ordering::Release);
        Some(value)
    }
}

impl<T, const N: usize> Drop for ValidateQueue<T, N> {
    fn drop(&mut self) {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        let len = tail.wrapping_sub(head);
        if len == 0 {
            return;
        }
        let buf = unsafe { &mut *self.buf.get() };
        for offset in 0..len {
            let idx = head.wrapping_add(offset) % N;
            unsafe {
                buf[idx].assume_init_drop();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ValidateQueue;

    #[test]
    fn push_pop_roundtrip() {
        let q: ValidateQueue<u32, 4> = ValidateQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.pop(), None);

        assert_eq!(q.push(1), Ok(()));
        assert_eq!(q.push(2), Ok(()));
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));
        assert!(q.is_empty());
    }

    #[test]
    fn full_and_wrap() {
        let q: ValidateQueue<u32, 2> = ValidateQueue::new();
        assert_eq!(q.push(10), Ok(()));
        assert_eq!(q.push(11), Ok(()));
        assert!(q.is_full());
        assert_eq!(q.push(12), Err(12));

        assert_eq!(q.pop(), Some(10));
        assert_eq!(q.push(12), Ok(()));
        assert_eq!(q.pop(), Some(11));
        assert_eq!(q.pop(), Some(12));
        assert_eq!(q.pop(), None);
    }
}
